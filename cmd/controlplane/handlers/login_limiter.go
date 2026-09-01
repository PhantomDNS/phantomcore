// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"sync"
	"time"
)

// Login brute-force protection: after loginMaxAttempts failed attempts from
// the same client IP within loginLockoutWindow, further attempts from that
// IP are rejected (429) until the window elapses. A successful login clears
// the IP's history immediately.
const (
	loginMaxAttempts   = 5
	loginLockoutWindow = 15 * time.Minute
)

// loginFailureRecord tracks failed login attempts from a single IP within
// the current lockout window.
type loginFailureRecord struct {
	count       int
	windowStart time.Time
}

// loginLimiter is a thread-safe, per-client-IP login attempt limiter. It is
// deliberately simple (in-memory, no external deps, state lost on restart):
// it guards a single low-traffic endpoint against brute force, not a hard
// security boundary.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string]*loginFailureRecord

	// now is injectable so tests can drive time deterministically without
	// real sleeps. It defaults to time.Now.
	now func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		failures: make(map[string]*loginFailureRecord),
		now:      time.Now,
	}
}

// allowed reports whether ip may attempt a login right now. A stale record
// (its window has elapsed) is treated as if it did not exist and is pruned.
func (l *loginLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.failures[ip]
	if !ok {
		return true
	}
	if l.now().Sub(rec.windowStart) >= loginLockoutWindow {
		delete(l.failures, ip)
		return true
	}
	return rec.count < loginMaxAttempts
}

// recordFailure registers a failed login attempt from ip, starting a fresh
// window if none is active or the previous one has expired.
func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	rec, ok := l.failures[ip]
	if !ok || now.Sub(rec.windowStart) >= loginLockoutWindow {
		rec = &loginFailureRecord{windowStart: now}
		l.failures[ip] = rec
	}
	rec.count++
}

// recordSuccess clears ip's failure history, e.g. after a successful login.
func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}
