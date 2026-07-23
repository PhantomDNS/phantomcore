// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"sync"
	"time"
)

// nodDefaultMaxEntries bounds the ledger's memory footprint. Once the ledger is
// full, the oldest first-seen entries are evicted to make room for new domains.
const nodDefaultMaxEntries = 100_000

// nodLedger is a bounded, thread-safe record of the first time each domain was
// observed on THIS resolver instance. It backs newly-observed-domain (NOD)
// detection: a domain whose first-seen timestamp still falls within the
// configured window is considered "newly observed".
//
// The ledger is in-memory only and does NOT survive a restart: after a restart
// every domain looks new until the window elapses again. This is an accepted
// tradeoff for v1 — a persistent backing store can be layered on later without
// changing this type's API.
type nodLedger struct {
	mu         sync.Mutex
	firstSeen  map[string]time.Time
	window     time.Duration
	maxEntries int
	// now is injectable so tests can drive time deterministically. Defaults to
	// time.Now when nil is passed to newNODLedger.
	now func() time.Time
}

// newNODLedger builds a ledger with the given first-seen window. A maxEntries of
// zero (or negative) falls back to nodDefaultMaxEntries; a nil now falls back to
// time.Now.
func newNODLedger(window time.Duration, maxEntries int, now func() time.Time) *nodLedger {
	if maxEntries <= 0 {
		maxEntries = nodDefaultMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &nodLedger{
		firstSeen:  make(map[string]time.Time),
		window:     window,
		maxEntries: maxEntries,
		now:        now,
	}
}

// observe records the domain (on first sight) and reports whether it is "newly
// observed" — i.e. its first-seen timestamp is within the configured window
// relative to now. The first time a domain is seen it is always new, since its
// first-seen timestamp equals now.
func (l *nodLedger) observe(domain string) (isNew bool) {
	if domain == "" {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	first, ok := l.firstSeen[domain]
	if !ok {
		l.evictIfFullLocked()
		l.firstSeen[domain] = now
		return true
	}
	return now.Sub(first) < l.window
}

// size reports the number of tracked domains. Intended for tests and diagnostics.
func (l *nodLedger) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.firstSeen)
}

// evictIfFullLocked drops the oldest first-seen entry once the ledger reaches
// its cap, keeping memory bounded by maxEntries. The caller must hold l.mu.
func (l *nodLedger) evictIfFullLocked() {
	if len(l.firstSeen) < l.maxEntries {
		return
	}
	// Evict the single oldest entry by first-seen time. The O(n) scan only runs
	// when the ledger is at capacity, and the map is bounded by maxEntries.
	var (
		oldestKey  string
		oldestTime time.Time
		found      bool
	)
	for k, t := range l.firstSeen {
		if !found || t.Before(oldestTime) {
			oldestKey = k
			oldestTime = t
			found = true
		}
	}
	if found {
		delete(l.firstSeen, oldestKey)
	}
}
