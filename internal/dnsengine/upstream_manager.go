// Handles upstream DNS resolvers with connection pooling, retry, and failover.
// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"math/rand"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

type UpstreamManager struct {
	pools []*UpstreamPool
	// dns0x20 enables DNS 0x20 case-randomization on outbound queries.
	// When false the send path behaves exactly as before.
	dns0x20 bool
}

// UpstreamOption customizes an UpstreamManager at construction time.
type UpstreamOption func(*UpstreamManager)

// WithDNS0x20 toggles DNS 0x20 case-randomization on outbound upstream queries.
func WithDNS0x20(enabled bool) UpstreamOption {
	return func(m *UpstreamManager) { m.dns0x20 = enabled }
}

// NewUpstreamManager builds a pool for each configured resolver
func NewUpstreamManager(resolvers []string, poolSize int, opts ...UpstreamOption) (*UpstreamManager, error) {
	manager := &UpstreamManager{}
	for _, opt := range opts {
		opt(manager)
	}
	for _, addr := range resolvers {
		pool, err := NewUpstreamPool(addr, poolSize)
		if err != nil {
			return nil, err
		}
		manager.pools = append(manager.pools, pool)
	}
	return manager, nil
}

func (m *UpstreamManager) Close() {
	for _, pool := range m.pools {
		pool.Close()
	}
}

// prepareOutbound returns the message to send upstream and the original
// question names for later restoration. When 0x20 is disabled it returns q
// unchanged and a nil originals slice (restoration becomes a no-op), so the
// send path is byte-for-byte identical to the pre-0x20 behaviour.
func (m *UpstreamManager) prepareOutbound(q *dns.Msg, r *rand.Rand) (*dns.Msg, []string) {
	if !m.dns0x20 || q == nil {
		return q, nil
	}
	return encodeCase0x20(q, r)
}

// Exchange forwards query to resolvers with retry+failover
func (m *UpstreamManager) Exchange(q *dns.Msg, timeout time.Duration, maxRetries int) (*dns.Msg, error) {
	var r *rand.Rand
	if m.dns0x20 {
		r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	outbound, originals := m.prepareOutbound(q, r)

	var lastErr error
	for _, pool := range m.pools {
		for attempt := 0; attempt < maxRetries; attempt++ {
			resp, err := pool.Exchange(outbound, timeout)
			if err == nil {
				if originals != nil {
					restoreCase0x20(resp, originals)
				}
				return resp, nil
			}
			lastErr = err
			logger.Log.Warnf("upstream %s failed (attempt %d): %v", pool.upstreamAddr, attempt+1, err)
		}
	}
	return nil, lastErr
}
