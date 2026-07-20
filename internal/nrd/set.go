// SPDX-License-Identifier: GPL-3.0-or-later

// Package nrd implements newly-registered-domain (NRD) blocking.
//
// An NRD feed is an operator-configured list of recently registered domains
// (external registration-date truth). It is maintained entirely separately from
// user blocklists and from the local first-seen ledger. When a feed is
// configured, a query whose domain or registrable parent appears on the feed is
// either blocked (respondBlocked reason "nrd") or, in flag mode, forwarded but
// flagged. With no feed configured the checker is inert.
package nrd

import "strings"

// Set is an immutable, read-optimized in-memory set of NRD domains. A nil or
// empty Set matches nothing, which makes the "no feed" case naturally inert.
type Set struct {
	domains map[string]struct{}
}

// NewSet builds a Set from a list of domains, normalizing and de-duplicating
// each entry. Blank entries are dropped.
func NewSet(domains []string) *Set {
	m := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if d = normalize(d); d != "" {
			m[d] = struct{}{}
		}
	}
	return &Set{domains: m}
}

// Len reports the number of domains in the set. Safe on a nil receiver.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.domains)
}

// Contains reports whether the domain, or any of its parent domains down to the
// registrable parent, is present in the set. NRD feeds list registrable domains,
// so a hit on "evil.com" also matches "login.evil.com". Safe on a nil receiver.
func (s *Set) Contains(domain string) bool {
	if s == nil || len(s.domains) == 0 {
		return false
	}
	d := normalize(domain)
	if d == "" {
		return false
	}
	// Exact match first, then walk up the parent labels but stop before the TLD:
	// "www.ads.evil.com" -> "ads.evil.com" -> "evil.com".
	parts := strings.Split(d, ".")
	for i := 0; i < len(parts)-1; i++ {
		if _, ok := s.domains[strings.Join(parts[i:], ".")]; ok {
			return true
		}
	}
	return false
}

// normalize lowercases, trims surrounding whitespace, and strips a trailing dot.
func normalize(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}
