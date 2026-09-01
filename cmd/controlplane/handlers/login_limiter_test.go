// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"fmt"
	"testing"
	"time"
)

// fixedClock returns a now func pinned at t, advanced by calling advance.
type fixedClock struct {
	t time.Time
}

func (c *fixedClock) now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestLoginLimiter_TableDriven(t *testing.T) {
	clock := &fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := newLoginLimiter()
	l.now = clock.now

	const ip = "203.0.113.7"

	// Under the limit: 4 failures should still allow a 5th attempt.
	for i := 0; i < loginMaxAttempts-1; i++ {
		if !l.allowed(ip) {
			t.Fatalf("attempt %d: expected allowed before hitting the limit", i+1)
		}
		l.recordFailure(ip)
	}

	// The loginMaxAttempts-th attempt is still allowed (it's the one that
	// trips the counter to the limit)...
	if !l.allowed(ip) {
		t.Fatal("expected the attempt that reaches the limit to still be allowed")
	}
	l.recordFailure(ip)

	// ...but the next one, over the limit, must be rejected.
	if l.allowed(ip) {
		t.Fatal("expected attempt over the limit to be rejected")
	}

	// A different IP is unaffected.
	if !l.allowed("198.51.100.9") {
		t.Fatal("expected an unrelated IP to be unaffected by another IP's lockout")
	}

	// Window expiry resets the counter.
	clock.advance(loginLockoutWindow)
	if !l.allowed(ip) {
		t.Fatal("expected lockout to clear once the window has elapsed")
	}

	// Trip the limiter again, then a success must reset it immediately.
	for i := 0; i < loginMaxAttempts; i++ {
		l.recordFailure(ip)
	}
	if l.allowed(ip) {
		t.Fatal("expected ip to be locked out after loginMaxAttempts failures")
	}
	l.recordSuccess(ip)
	if !l.allowed(ip) {
		t.Fatal("expected a successful login to clear the lockout immediately")
	}
}

func TestLoginLimiter_RecordFailure_ExpiredWindowStartsFresh(t *testing.T) {
	clock := &fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := newLoginLimiter()
	l.now = clock.now

	const ip = "203.0.113.7"
	for i := 0; i < loginMaxAttempts; i++ {
		l.recordFailure(ip)
	}
	if l.allowed(ip) {
		t.Fatal("expected lockout after loginMaxAttempts failures")
	}

	// Advance well past the window without ever calling allowed()/recordSuccess.
	clock.advance(loginLockoutWindow * 2)

	// A new failure after the window expired should start a fresh window,
	// not add to the stale count.
	l.recordFailure(ip)
	if !l.allowed(ip) {
		t.Fatal("expected a single failure in a fresh window to still be under the limit")
	}
}

func TestLoginLimiter_ConcurrentAccess(t *testing.T) {
	l := newLoginLimiter()
	const ip = "203.0.113.7"

	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			l.allowed(ip)
			l.recordFailure(ip)
			l.recordSuccess(ip)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestLoginLimiter_BoundsTrackedIPs(t *testing.T) {
	clock := &fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := newLoginLimiter()
	l.now = clock.now

	for i := 0; i < loginMaxTrackedIPs; i++ {
		l.recordFailure(fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	if len(l.failures) != loginMaxTrackedIPs {
		t.Fatalf("tracked IPs = %d, want %d", len(l.failures), loginMaxTrackedIPs)
	}

	// A new IP at capacity must not grow the map; one record is evicted and
	// the new failure is still recorded.
	l.recordFailure("192.168.1.1")
	if len(l.failures) > loginMaxTrackedIPs {
		t.Errorf("map grew past cap: %d", len(l.failures))
	}
	if _, ok := l.failures["192.168.1.1"]; !ok {
		t.Error("new failure was not recorded at capacity")
	}

	// Once the window lapses, the sweep drops expired records wholesale.
	clock.advance(loginLockoutWindow + time.Second)
	l.recordFailure("172.16.0.1")
	if len(l.failures) != 1 {
		t.Errorf("expired records not swept: len = %d, want 1", len(l.failures))
	}
}
