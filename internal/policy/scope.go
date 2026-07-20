package policy

import (
	"fmt"
	"net"
	"strings"
)

// parseClientScope parses a single client-scope entry into an *net.IPNet.
// An entry may be a CIDR ("10.0.0.0/24") or a bare IP ("192.168.1.10"),
// IPv4 or IPv6. A bare IP is treated as a host route (/32 or /128).
func parseClientScope(entry string) (*net.IPNet, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, fmt.Errorf("empty client scope entry")
	}
	if strings.Contains(entry, "/") {
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, err
		}
		return ipnet, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP or CIDR %q", entry)
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// parseClientIP extracts a net.IP from a raw client address. The dataplane
// hands us the value of net.Addr.String(), which is "host:port" (e.g.
// "192.168.1.10:5353" or "[::1]:53"); tests and some callers may pass a bare
// IP. Returns nil when the address cannot be parsed.
func parseClientIP(raw string) net.IP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return net.ParseIP(raw)
}

// matchesClient reports whether policy p applies to the given client IP.
//
// Fast path: an unscoped policy (no ClientCIDRs) applies to every client,
// so it matches unconditionally and never touches the parsed-net map. A
// scoped policy matches only when the client IP falls inside one of its
// ranges; if the client IP is unknown (nil) or none of the ranges parsed,
// a scoped policy does not match.
func (s *PolicySnapshot) matchesClient(p *Policy, clientIP net.IP) bool {
	if p == nil {
		return false
	}
	if len(p.ClientCIDRs) == 0 {
		return true // unscoped: applies to all clients
	}
	if clientIP == nil {
		return false // scoped policy needs a known client IP
	}
	for _, n := range s.clientNets[p.ID] {
		if n.Contains(clientIP) {
			return true
		}
	}
	return false
}
