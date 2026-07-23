// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeClock is a manually advanced clock for deterministic, sleep-free tests.
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(perSec int, clk *fakeClock) *rateLimiter {
	rl := newRateLimiter(perSec)
	rl.now = clk.now
	return rl
}

func TestRateLimiter_UnderLimitAllowed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	rl := newTestLimiter(5, clk)

	for i := 0; i < 5; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("query %d within limit should be allowed", i+1)
		}
	}
}

func TestRateLimiter_OverLimitDenied(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	rl := newTestLimiter(3, clk)

	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("query %d within limit should be allowed", i+1)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("query over the limit should be denied")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("subsequent query over the limit should stay denied")
	}
}

func TestRateLimiter_WindowResets(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	rl := newTestLimiter(2, clk)

	if !rl.allow("10.0.0.1") || !rl.allow("10.0.0.1") {
		t.Fatal("first two queries should be allowed")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("third query in the same window should be denied")
	}

	// Advance past the one-second window; the counter must reset.
	clk.advance(time.Second)
	if !rl.allow("10.0.0.1") {
		t.Fatal("query should be allowed after the window resets")
	}
	if !rl.allow("10.0.0.1") {
		t.Fatal("second query in the new window should be allowed")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("third query in the new window should be denied")
	}
}

func TestRateLimiter_PartialWindowDoesNotReset(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	rl := newTestLimiter(2, clk)

	if !rl.allow("10.0.0.1") || !rl.allow("10.0.0.1") {
		t.Fatal("first two queries should be allowed")
	}
	// Less than a full second: still the same window, still denied.
	clk.advance(500 * time.Millisecond)
	if rl.allow("10.0.0.1") {
		t.Fatal("query within the same window should be denied")
	}
}

func TestRateLimiter_ClientsIndependent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	rl := newTestLimiter(1, clk)

	if !rl.allow("10.0.0.1") {
		t.Fatal("first client's first query should be allowed")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("first client's second query should be denied")
	}
	// A different client has its own budget and is unaffected.
	if !rl.allow("10.0.0.2") {
		t.Fatal("second client's first query should be allowed")
	}
	if rl.allow("10.0.0.2") {
		t.Fatal("second client's second query should be denied")
	}
}

func TestRateLimiter_DisabledAllowsAll(t *testing.T) {
	for _, perSec := range []int{0, -1} {
		clk := &fakeClock{t: time.Unix(0, 0)}
		rl := newTestLimiter(perSec, clk)
		for i := 0; i < 1000; i++ {
			if !rl.allow("10.0.0.1") {
				t.Fatalf("perSec=%d should allow all queries, denied at %d", perSec, i)
			}
		}
	}
}

func TestRateLimiter_NilReceiverAllows(t *testing.T) {
	var rl *rateLimiter
	if !rl.allow("10.0.0.1") {
		t.Fatal("nil limiter should allow all queries")
	}
}

func TestRateLimiter_EvictsIdleClients(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	rl := newTestLimiter(1, clk)
	rl.maxClients = 2

	rl.allow("10.0.0.1")
	rl.allow("10.0.0.2")
	if len(rl.clients) != 2 {
		t.Fatalf("expected 2 tracked clients, got %d", len(rl.clients))
	}

	// Move well past the idle threshold, then add a new client. The full map
	// triggers an idle sweep that clears the two stale entries.
	clk.advance(rateLimitIdleEvict + time.Second)
	rl.allow("10.0.0.3")
	if _, ok := rl.clients["10.0.0.1"]; ok {
		t.Error("idle client 10.0.0.1 should have been evicted")
	}
	if _, ok := rl.clients["10.0.0.2"]; ok {
		t.Error("idle client 10.0.0.2 should have been evicted")
	}
	if _, ok := rl.clients["10.0.0.3"]; !ok {
		t.Error("active client 10.0.0.3 should be tracked")
	}
}

// TestProcessDNSQuery_RateLimited exercises the limiter through the engine's
// request path: the second query from the same client in one window is REFUSED.
func TestProcessDNSQuery_RateLimited(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, nil)
	rl := newRateLimiter(1)
	rl.now = clk.now
	e.rateLimiter = rl

	// First query is under the limit. With no upstream manager configured the
	// forward path is not what we assert here; a fresh writer keeps it isolated.
	w1 := &mockResponseWriter{}
	func() {
		defer func() { _ = recover() }() // forwardUpstream has no upstream in tests
		e.ProcessDNSQuery(w1, newTestQuery("example.com"))
	}()

	// Second query in the same window must be refused before any forwarding.
	w2 := &mockResponseWriter{}
	e.ProcessDNSQuery(w2, newTestQuery("example.com"))
	if w2.msg == nil {
		t.Fatal("expected a REFUSED response for the rate-limited query")
	}
	if w2.msg.Rcode != dns.RcodeRefused {
		t.Errorf("expected REFUSED rcode for rate-limited query, got %d", w2.msg.Rcode)
	}
}
