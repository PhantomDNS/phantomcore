// Handles upstream DNS resolvers with connection pooling, retry, and failover.
// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

// Resolver schemes supported in the upstream configuration. A resolver entry
// may be written as:
//
//	1.1.1.1:53                            plain UDP/TCP (default, unchanged)
//	udp://1.1.1.1:53                      explicit plain UDP/TCP
//	tls://1.1.1.1:853                     DNS-over-TLS (DoT, RFC 7858)
//	https://cloudflare-dns.com/dns-query  DNS-over-HTTPS (DoH, RFC 8484)
const (
	schemePlain = "plain"
	schemeUDP   = "udp"
	schemeDoT   = "tls"
	schemeDoH   = "https"

	defaultDoTPort = "853"
)

// Upstream is a single outbound resolver. The plain UDP/TCP pool, the DoT
// client and the DoH client all satisfy this interface, so UpstreamManager can
// treat them uniformly for pooling/failover.
type Upstream interface {
	// Exchange sends a query and returns the response.
	Exchange(q *dns.Msg, timeout time.Duration) (*dns.Msg, error)
	// Close releases any resources held by the upstream.
	Close() error
	// Addr returns a human-readable identifier used for logging.
	Addr() string
}

type UpstreamManager struct {
	upstreams []Upstream
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

// NewUpstreamManager builds an upstream for each configured resolver. The
// resolver scheme selects the transport; entries with no scheme (or "udp://")
// use the existing plain UDP/TCP path unchanged.
func NewUpstreamManager(resolvers []string, poolSize int, opts ...UpstreamOption) (*UpstreamManager, error) {
	manager := &UpstreamManager{}
	for _, opt := range opts {
		opt(manager)
	}
	for _, entry := range resolvers {
		up, err := newUpstream(entry, poolSize)
		if err != nil {
			return nil, err
		}
		manager.upstreams = append(manager.upstreams, up)
	}
	return manager, nil
}

// newUpstream parses the resolver scheme and constructs the matching transport.
func newUpstream(entry string, poolSize int) (Upstream, error) {
	scheme, target, err := parseResolverScheme(entry)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case schemePlain:
		return NewUpstreamPool(target, poolSize)
	case schemeDoT:
		return newDoTClient(target)
	case schemeDoH:
		return newDoHClient(target)
	default:
		return nil, fmt.Errorf("unsupported resolver scheme %q in %q", scheme, entry)
	}
}

// parseResolverScheme splits a resolver entry into a normalized scheme and the
// transport-specific target. Entries without a "scheme://" prefix, and "udp://"
// entries, are treated as plain UDP/TCP. For DoT the returned target is a
// host:port (defaulting to :853); for DoH it is the full https URL.
func parseResolverScheme(entry string) (scheme, target string, err error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", "", errors.New("empty resolver entry")
	}

	idx := strings.Index(entry, "://")
	if idx < 0 {
		// No scheme: plain UDP/TCP, unchanged behavior.
		return schemePlain, entry, nil
	}

	scheme = strings.ToLower(entry[:idx])
	rest := entry[idx+len("://"):]

	switch scheme {
	case schemeUDP, schemePlain:
		if rest == "" {
			return "", "", fmt.Errorf("resolver %q missing host", entry)
		}
		return schemePlain, rest, nil
	case schemeDoT:
		if rest == "" {
			return "", "", fmt.Errorf("resolver %q missing host", entry)
		}
		return schemeDoT, ensurePort(rest, defaultDoTPort), nil
	case schemeDoH:
		// The full URL (including scheme) is needed by the HTTP client.
		return schemeDoH, entry, nil
	default:
		return "", "", fmt.Errorf("unsupported resolver scheme %q in %q", scheme, entry)
	}
}

// ensurePort appends defPort to host when host has no port component.
func ensurePort(host, defPort string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defPort)
}

func (m *UpstreamManager) Close() {
	for _, up := range m.upstreams {
		_ = up.Close()
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
	for _, up := range m.upstreams {
		for attempt := 0; attempt < maxRetries; attempt++ {
			resp, err := up.Exchange(outbound, timeout)
			if err == nil {
				if originals != nil {
					restoreCase0x20(resp, originals)
				}
				return resp, nil
			}
			lastErr = err
			logger.Log.Warnf("upstream %s failed (attempt %d): %v", up.Addr(), attempt+1, err)
		}
	}
	return nil, lastErr
}
