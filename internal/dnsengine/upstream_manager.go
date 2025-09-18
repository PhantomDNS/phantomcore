// Handles upstream DNS resolvers with connection pooling, retry, and failover.
package dnsengine

import (
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

type UpstreamManager struct {
	pools []*UpstreamPool
}

// NewUpstreamManager builds a pool for each configured resolver
func NewUpstreamManager(resolvers []string, poolSize int) (*UpstreamManager, error) {
	manager := &UpstreamManager{}
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

// Exchange forwards query to resolvers with retry+failover
func (m *UpstreamManager) Exchange(q *dns.Msg, timeout time.Duration, maxRetries int) (*dns.Msg, error) {
	var lastErr error
	for _, pool := range m.pools {
		for attempt := 0; attempt < maxRetries; attempt++ {
			resp, err := pool.Exchange(q, timeout)
			if err == nil {
				return resp, nil
			}
			lastErr = err
			logger.Log.Warnf("upstream %s failed (attempt %d): %v", pool.upstreamAddr, attempt+1, err)
		}
	}
	return nil, lastErr
}
