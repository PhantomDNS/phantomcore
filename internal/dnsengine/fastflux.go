// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Fast-flux tracker defaults. The IP-count and TTL thresholds are configurable
// via config; the sliding window and domain cap are fixed sensible defaults.
const (
	defaultFastFluxWindow     = 5 * time.Minute
	defaultFastFluxMaxDomains = 4096
	defaultFastFluxIPThresh   = 8
	defaultFastFluxTTLMaxSec  = 300
)

// ipRecord tracks the last time a distinct answer IP was seen for a domain and
// the TTL that came with that answer.
type ipRecord struct {
	lastSeen time.Time
	ttl      uint32
}

// ffDomainEntry holds the set of distinct answer IPs observed for one domain
// within the sliding window, keyed by IP string for O(1) dedup.
type ffDomainEntry struct {
	ips      map[string]ipRecord
	lastSeen time.Time
}

// fastFluxTracker is a bounded, thread-safe, per-domain tracker of the distinct
// answer IPs seen within a sliding time window along with the minimum TTL
// observed. It is used to FLAG (never block) domains exhibiting fast-flux
// behaviour: many distinct low-TTL IPs churning over a short window, classic of
// botnet / C2 infrastructure. CDNs also rotate IPs but keep the distinct-IP
// count modest per window, so the threshold is set conservatively.
//
// Memory is bounded two ways: the number of tracked domains is capped (oldest
// idle domain evicted on overflow), and per-domain IP records are pruned once
// they fall outside the window.
type fastFluxTracker struct {
	mu          sync.Mutex
	domains     map[string]*ffDomainEntry
	window      time.Duration
	ipThreshold int
	ttlMax      uint32
	maxDomains  int
	now         func() time.Time
}

// newFastFluxTracker builds a tracker. Non-positive values fall back to
// defaults. clock is injectable for deterministic testing; nil means time.Now.
func newFastFluxTracker(ipThreshold, ttlMaxSec int, window time.Duration, maxDomains int, clock func() time.Time) *fastFluxTracker {
	if ipThreshold <= 0 {
		ipThreshold = defaultFastFluxIPThresh
	}
	if ttlMaxSec <= 0 {
		ttlMaxSec = defaultFastFluxTTLMaxSec
	}
	if window <= 0 {
		window = defaultFastFluxWindow
	}
	if maxDomains <= 0 {
		maxDomains = defaultFastFluxMaxDomains
	}
	if clock == nil {
		clock = time.Now
	}
	return &fastFluxTracker{
		domains:     make(map[string]*ffDomainEntry),
		window:      window,
		ipThreshold: ipThreshold,
		ttlMax:      uint32(ttlMaxSec),
		maxDomains:  maxDomains,
		now:         clock,
	}
}

// observe records the answer IPs and their (minimum) TTL for a domain and
// reports whether the domain currently looks like fast-flux: at least
// ipThreshold distinct IPs seen within the sliding window AND a minimum observed
// TTL <= ttlMax. It never blocks; the boolean is advisory only.
//
// A nil tracker is treated as "disabled" and always returns false, so callers
// can gate purely on the config without a separate flag.
func (t *fastFluxTracker) observe(domain string, ips []net.IP, ttl uint32) bool {
	if t == nil || domain == "" || len(ips) == 0 {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()

	entry := t.domains[domain]
	if entry == nil {
		// Enforce the domain cap before inserting a brand-new entry.
		if len(t.domains) >= t.maxDomains {
			t.evictOldestLocked()
		}
		entry = &ffDomainEntry{ips: make(map[string]ipRecord)}
		t.domains[domain] = entry
	}

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		entry.ips[ip.String()] = ipRecord{lastSeen: now, ttl: ttl}
	}
	entry.lastSeen = now

	// Prune IPs whose most recent observation has fallen outside the window and
	// compute the minimum TTL across the survivors in the same pass.
	cutoff := now.Add(-t.window)
	minTTL := ^uint32(0)
	for k, rec := range entry.ips {
		if rec.lastSeen.Before(cutoff) {
			delete(entry.ips, k)
			continue
		}
		if rec.ttl < minTTL {
			minTTL = rec.ttl
		}
	}

	// Everything expired: drop the domain to keep memory bounded.
	if len(entry.ips) == 0 {
		delete(t.domains, domain)
		return false
	}

	return len(entry.ips) >= t.ipThreshold && minTTL <= t.ttlMax
}

// evictOldestLocked removes the least-recently-seen domain entry. The caller
// must hold t.mu.
func (t *fastFluxTracker) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range t.domains {
		if first || e.lastSeen.Before(oldest) {
			oldest, oldestKey, first = e.lastSeen, k, false
		}
	}
	if oldestKey != "" {
		delete(t.domains, oldestKey)
	}
}

// extractAnswerIPs pulls A/AAAA record IPs and the minimum TTL from a DNS
// response. ok is false when the response carries no address records.
func extractAnswerIPs(resp *dns.Msg) (ips []net.IP, minTTL uint32, ok bool) {
	if resp == nil {
		return nil, 0, false
	}
	minTTL = ^uint32(0)
	for _, rr := range resp.Answer {
		switch rec := rr.(type) {
		case *dns.A:
			ips = append(ips, rec.A)
			if rec.Hdr.Ttl < minTTL {
				minTTL = rec.Hdr.Ttl
			}
		case *dns.AAAA:
			ips = append(ips, rec.AAAA)
			if rec.Hdr.Ttl < minTTL {
				minTTL = rec.Hdr.Ttl
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, false
	}
	return ips, minTTL, true
}
