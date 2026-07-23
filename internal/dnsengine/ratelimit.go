// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"sync"
	"time"
)

// Bounds for the per-client rate limiter's memory footprint. Idle clients are
// evicted lazily so a large, churning client population cannot grow the map
// without limit.
const (
	rateLimitMaxClients = 65536
	rateLimitIdleEvict  = 10 * time.Second
)

// clientWindow tracks the fixed one-second window state for a single client IP.
type clientWindow struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

// rateLimiter is a thread-safe, per-client-IP fixed-window rate limiter. It
// allows up to perSec queries per client per second. When perSec <= 0 it is a
// no-op that allows everything, so it is always safe to construct and call.
type rateLimiter struct {
	perSec     int
	maxClients int
	idleAfter  time.Duration

	mu      sync.Mutex
	clients map[string]*clientWindow

	// now is injectable so tests can drive time deterministically without
	// real sleeps. It defaults to time.Now.
	now func() time.Time
}

// newRateLimiter builds a limiter capped at perSec queries per client IP each
// second. A perSec <= 0 yields an allow-all limiter (rate limiting disabled).
func newRateLimiter(perSec int) *rateLimiter {
	return &rateLimiter{
		perSec:     perSec,
		maxClients: rateLimitMaxClients,
		idleAfter:  rateLimitIdleEvict,
		clients:    make(map[string]*clientWindow),
		now:        time.Now,
	}
}

// allow reports whether a query from clientIP may proceed. It returns true
// (allow) when rate limiting is disabled (perSec <= 0) or the limiter is nil,
// so callers need not special-case those states.
func (rl *rateLimiter) allow(clientIP string) bool {
	if rl == nil || rl.perSec <= 0 {
		return true
	}

	now := rl.now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	w, ok := rl.clients[clientIP]
	if !ok {
		if len(rl.clients) >= rl.maxClients {
			rl.evictIdle(now)
		}
		w = &clientWindow{windowStart: now}
		rl.clients[clientIP] = w
	}

	// Roll to a fresh window once a full second has elapsed.
	if now.Sub(w.windowStart) >= time.Second {
		w.windowStart = now
		w.count = 0
	}

	w.lastSeen = now
	if w.count >= rl.perSec {
		return false
	}
	w.count++
	return true
}

// evictIdle removes clients that have not been seen within idleAfter. It must
// be called with rl.mu held. This is best-effort: if every tracked client is
// active the map may still exceed maxClients, but memory stays bounded by the
// active client population rather than growing forever.
func (rl *rateLimiter) evictIdle(now time.Time) {
	for ip, w := range rl.clients {
		if now.Sub(w.lastSeen) >= rl.idleAfter {
			delete(rl.clients, ip)
		}
	}
}
