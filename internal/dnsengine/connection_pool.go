package dnsengine

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

// This pool only needed for TCP connections
// For UDP we can reuse same single UDP socket
type UpstreamPool struct {
	inUse    []bool
	upstream string
	mu       sync.Mutex
	conns    []net.Conn
	maxConns int
	dialer   net.Dialer
}

func NewUpStreamPool(upstream string, maxConns int) *UpstreamPool {
	return &UpstreamPool{
		upstream: upstream,
		maxConns: maxConns,
		conns:    make([]net.Conn, 0, maxConns),
		inUse:    make([]bool, 0, maxConns),
		dialer:   net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}, // 2 seconds
	}
}

func (p *UpstreamPool) getConn() (net.Conn, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to find an available connection
	for i, inUse := range p.inUse {
		if !inUse {
			p.inUse[i] = true
			return p.conns[i], i, nil
		}
	}

	// If we have not reached maxConns, create a new connection
	if len(p.conns) < p.maxConns {
		newconn, err := p.dialer.Dial("tcp", p.upstream)
		if err != nil {
			return nil, -1, err
		}
		p.conns = append(p.conns, newconn)
		p.inUse = append(p.inUse, true)
		return newconn, len(p.conns) - 1, nil
	}

	// All connections are in use and we've reached maxConns
	return nil, -1, errors.New("upstream pool exhausted")
}

// release a connection back to the pool to be available for reuse
// or discards connection if it's broken or error
func (p *UpstreamPool) releaseConn(idx int, conn net.Conn, hadErr bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if hadErr || conn == nil {
		if conn != nil {
			conn.Close()
		}
		p.conns[idx] = nil
		p.inUse[idx] = false
		logger.Log.Warnf("Dropped bad connection to upstream %s", p.upstream)
		return
	}

	p.inUse[idx] = false
}

// exchange means forwarding DNS query to upstream resolver
func (p *UpstreamPool) Exchange(q *dns.Msg) (*dns.Msg, error) {
	// todo: add a udp path first then use TCP at fallback

	conn, idx, err := p.getConn()
	if err != nil {
		return nil, err
	}

	var hadErr bool
	defer func() { p.releaseConn(idx, conn, hadErr) }()

	// wrap pooled connection with dns.conn
	dnsConn := &dns.Conn{Conn: conn}

	// apply per query timeout
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second)) // 2 seconds

	// write query
	if err := dnsConn.WriteMsg(q); err != nil {
		hadErr = true
		return nil, err
	}

	// read response
	resp, err := dnsConn.ReadMsg()
	if err != nil {
		hadErr = true
		return nil, err
	}
	return resp, nil
}
