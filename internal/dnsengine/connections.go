// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

const (
	defaultDialTimeout  = 5 * time.Second
	defaultQueryTimeout = 5 * time.Second
	defaultKeepAlive    = 30 * time.Second
	maxRetries          = 3
)

// UDPClient is a small wrapper around a reusable UDP socket for a single upstream.
// We serialize access with a mutex because we use the same socket for many goroutines.
type UDPClient struct {
	upstreamAddr string
	mu           sync.Mutex
	conn         *dns.Conn
}

func newUDPClient(upstreamAddr string) (*UDPClient, error) {
	d := net.Dialer{Timeout: defaultDialTimeout, KeepAlive: defaultKeepAlive}
	raw, err := d.Dial("udp", upstreamAddr)
	if err != nil {
		return nil, err
	}
	return &UDPClient{
		upstreamAddr: upstreamAddr,
		conn:         &dns.Conn{Conn: raw},
	}, nil
}

// Exchange sends a query and reads a response using the shared UDP socket.
// It serializes access and applies the provided timeout.
func (u *UDPClient) Exchange(q *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if err := u.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := u.conn.WriteMsg(q); err != nil {
		return nil, err
	}
	resp, err := u.conn.ReadMsg()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close closes the underlying UDP socket.
func (u *UDPClient) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn == nil {
		return nil
	}
	err := u.conn.Close()
	u.conn = nil
	return err
}

// UpstreamPool manages outbound queries to a single upstream resolver.
// - UDP: a single long-lived socket (UDPClient) is used for the fast path.
// - TCP: a small pool of persistent TCP connections is maintained and reused.
type UpstreamPool struct {
	upstreamAddr string
	// UDP client (fast path)
	udp *UDPClient
	// TCP pool
	mu       sync.Mutex
	conns    []*net.TCPConn // fixed length == maxConns
	inUse    []bool
	maxConns int
	next     int // simple round-robin cursor for fairness
	// dialer used to create new TCP connections
	dialer net.Dialer
	closed bool
}

// NewUpstreamPool creates a pool for the given upstream address.
// maxConns must be >= 1 (the number of TCP connections to maintain).
func NewUpstreamPool(upstreamAddr string, maxConns int) (*UpstreamPool, error) {
	if maxConns < 1 {
		return nil, errors.New("maxConns must be >= 1")
	}

	udp, err := newUDPClient((upstreamAddr))
	if err != nil {
		return nil, err
	}

	// Preallocate fixed-size slices for easier invariant reasoning.
	conns := make(([]*net.TCPConn), maxConns)
	inUse := make([]bool, maxConns)

	return &UpstreamPool{
		upstreamAddr: upstreamAddr,
		udp:          udp,
		conns:        conns,
		inUse:        inUse,
		maxConns:     maxConns,
		dialer: net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultKeepAlive,
		},
	}, nil
}

// Close shuts down the pool and closes all sockets. It is safe to call multiple times.
func (p *UpstreamPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true

	var firstErr error
	if err := p.udp.Close(); firstErr == nil && err != nil {
		firstErr = err
	}
	for i, conn := range p.conns {
		if conn != nil {
			if err := conn.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
			p.conns[i] = nil
			p.inUse[i] = false
		}
	}
	return firstErr
}

// getTCPConn returns an index and an active *net.TCPConn. If a slot contains nil,
// it will attempt to dial and fill that slot. If all slots are busy, returns error.
// Note: caller must call releaseTCPConn(idx, hadErr) when done.
func (p *UpstreamPool) getTCPConn() (*net.TCPConn, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, -1, errors.New("upstream pool is closed")
	}

	// Simple round-robin to ensure fairness.
	start := p.next
	for i := 0; i < p.maxConns; i++ {
		idx := (start + i) % p.maxConns
		if !p.inUse[idx] {
			// reserve a slot
			p.inUse[idx] = true
			p.next = (idx + 1) % p.maxConns
			// if there's already a connection, return it
			if p.conns[idx] != nil {
				return p.conns[idx], idx, nil
			}
			// otherwise, try to dial a new connection
			// mark that slot as expected to be filled; but we already set inUse true so others won't take it.
			p.mu.Unlock() // unlock while dialing
			raw, err := p.dialer.Dial("tcp", p.upstreamAddr)
			p.mu.Lock() // relock to update state
			if err != nil {
				p.inUse[idx] = false // release the slot on error
				return nil, -1, err
			}
			// successful dial: store typed *net.TCPConn
			if tcp, ok := raw.(*net.TCPConn); ok {
				p.conns[idx] = tcp
				return tcp, idx, nil
			}
			// unlikely: non-TCP conn returned
			_ = raw.Close()
			p.inUse[idx] = false
			return nil, -1, errors.New("unexpected non-tcp connection")
		}
	}
	// all slots are busy
	return nil, -1, errors.New("upstream pool exhausted")
}

// releaseTCPConn releases the connection at index idx back to the pool.
// If hadErr is true, the connection is closed and the slot becomes nil.
func (p *UpstreamPool) releaseTCPConn(idx int, hadErr bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// guard index
	if idx < 0 || idx >= len(p.conns) {
		return
	}

	if hadErr {
		if p.conns[idx] != nil {
			_ = p.conns[idx].Close()
			p.conns[idx] = nil
		}
		p.inUse[idx] = false
	}
}

// Exchange implements the UDP-fastpath -> TCP-fallback behavior.
// 1) Try UDP with shared socket (fast). If UDP returns a response and TC == false, return it.
// 2) Otherwise (error or truncated), use a pooled TCP connection and return that response.
//
// Important: callers should not assume Exchange is cheap — it performs network IO and may block.
func (p *UpstreamPool) Exchange(q *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	// First, try UDP (fast path)
	if p.udp != nil {
		resp, err := p.udp.Exchange(q, defaultQueryTimeout)
		if err == nil && resp != nil && !resp.Truncated {
			return resp, nil
		}
		// else fall through to TCP fallback (either error or truncated)
	}

	// Fallback, TCP using pooled connections
	tcpConn, idx, err := p.getTCPConn()
	if err != nil {
		return nil, err
	}

	var hadErr bool
	defer p.releaseTCPConn(idx, hadErr)

	// wrap with dns.Conn for framing (length-prefix) and convenience
	dnsConn := &dns.Conn{Conn: tcpConn}
	if err := tcpConn.SetDeadline(time.Now().Add(defaultQueryTimeout)); err != nil {
		return nil, err
	}

	if err := dnsConn.WriteMsg(q); err != nil {
		hadErr = true
		logger.Log.Errorf("Failed to write DNS query to TCP connection: %v", err)
		return nil, err
	}

	resp, err := dnsConn.ReadMsg()
	if err != nil {
		hadErr = true
		logger.Log.Errorf("Failed to read DNS response from TCP connection: %v", err)
		return nil, err
	}
	return resp, nil
}
