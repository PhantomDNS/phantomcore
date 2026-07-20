// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mutableClock returns a now-func plus a pointer to advance it, so tests can
// drive the ledger deterministically with no real sleeps.
func mutableClock(start time.Time) (func() time.Time, *time.Time) {
	cur := start
	return func() time.Time { return cur }, &cur
}

// --- Ledger unit tests ---

func TestNODLedger_FirstSightIsNew(t *testing.T) {
	l := newNODLedger(time.Hour, 0, nil)
	if !l.observe("example.com") {
		t.Fatal("first sight of a domain should be new")
	}
}

func TestNODLedger_EmptyDomainNeverNew(t *testing.T) {
	l := newNODLedger(time.Hour, 0, nil)
	if l.observe("") {
		t.Error("empty domain should never be reported as new")
	}
	if l.size() != 0 {
		t.Errorf("empty domain should not be recorded, size=%d", l.size())
	}
}

func TestNODLedger_WithinWindowStillNew(t *testing.T) {
	clk, cur := mutableClock(time.Unix(1_700_000_000, 0))
	l := newNODLedger(time.Hour, 0, clk)

	if !l.observe("shop.example.com") {
		t.Fatal("first observation should be new")
	}
	// 30 minutes later — still inside the 1h window.
	*cur = cur.Add(30 * time.Minute)
	if !l.observe("shop.example.com") {
		t.Error("domain re-seen within the window should still be new")
	}
}

func TestNODLedger_NotNewAfterWindow(t *testing.T) {
	clk, cur := mutableClock(time.Unix(1_700_000_000, 0))
	l := newNODLedger(time.Hour, 0, clk)

	if !l.observe("late.example.com") {
		t.Fatal("first observation should be new")
	}
	// Advance past the window boundary.
	*cur = cur.Add(2 * time.Hour)
	if l.observe("late.example.com") {
		t.Error("domain first seen before the window elapsed should not be new after it passes")
	}
	// Exactly at the window boundary is also NOT new (>= window).
	clk2, cur2 := mutableClock(time.Unix(1_700_000_000, 0))
	l2 := newNODLedger(time.Hour, 0, clk2)
	l2.observe("edge.example.com")
	*cur2 = cur2.Add(time.Hour)
	if l2.observe("edge.example.com") {
		t.Error("domain exactly at the window boundary should not be new")
	}
}

func TestNODLedger_BoundedEviction(t *testing.T) {
	clk, cur := mutableClock(time.Unix(1_700_000_000, 0))
	// Cap at 2 entries so eviction is easy to force.
	l := newNODLedger(time.Hour, 2, clk)

	l.observe("a.com") // t0
	*cur = cur.Add(time.Minute)
	l.observe("b.com") // t0+1m
	if l.size() != 2 {
		t.Fatalf("expected size 2, got %d", l.size())
	}

	// Third distinct domain must evict the oldest ("a.com") to stay bounded.
	*cur = cur.Add(time.Minute)
	l.observe("c.com") // t0+2m
	if l.size() != 2 {
		t.Errorf("ledger exceeded cap: size=%d, want 2", l.size())
	}

	// "a.com" was evicted, so observing it again looks brand new.
	if !l.observe("a.com") {
		t.Error("evicted domain should be treated as newly observed again")
	}
	// Still bounded after re-inserting.
	if l.size() > 2 {
		t.Errorf("ledger exceeded cap after re-insert: size=%d", l.size())
	}
}

// --- Engine integration tests (block vs flag vs disabled) ---

// newNODEngine builds an allow-path-safe engine: an empty UpstreamManager makes
// forwardUpstream return SERVFAIL (nil response, no network I/O), so the flag
// path is deterministic and does not touch the network.
func newNODEngine(window time.Duration, block bool, clk func() time.Time) *Engine {
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, nil)
	e.setUpstreamExchanger(&UpstreamManager{}) // no pools -> Exchange returns nil,nil
	if window > 0 {
		e.nodLedger = newNODLedger(window, 0, clk)
	}
	e.nodBlock = block
	return e
}

func TestProcessDNSQuery_NODBlockMode(t *testing.T) {
	clk, _ := mutableClock(time.Unix(1_700_000_000, 0))
	e := newNODEngine(time.Hour, true, clk)

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("brand-new.com"))

	if w.msg == nil {
		t.Fatal("expected a response for a newly observed domain")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected NOD block (0.0.0.0) in block mode, got rcode %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_NODFlagMode(t *testing.T) {
	clk, _ := mutableClock(time.Unix(1_700_000_000, 0))
	e := newNODEngine(time.Hour, false, clk)

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("brand-new.com"))

	if w.msg == nil {
		t.Fatal("expected a response for a newly observed domain")
	}
	// Flag mode must NOT block; the query is forwarded (empty upstream -> SERVFAIL).
	if isBlockedResponse(w.msg) {
		t.Error("flag mode should not block a newly observed domain")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected forwarded query (SERVFAIL from empty upstream), got rcode %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_NODDisabled(t *testing.T) {
	// Disabled: nodLedger nil even though nodBlock would otherwise block.
	e := newNODEngine(0, true, nil)
	if e.nodLedger != nil {
		t.Fatal("ledger should be nil when NOD is disabled")
	}

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("brand-new.com"))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// With NOD off, a new domain is not blocked; it is forwarded normally.
	if isBlockedResponse(w.msg) {
		t.Error("disabled NOD must not block newly observed domains")
	}
}

func TestProcessDNSQuery_NODBlockThenAllowedAfterWindow(t *testing.T) {
	clk, cur := mutableClock(time.Unix(1_700_000_000, 0))
	e := newNODEngine(time.Hour, true, clk)

	// First sight -> blocked.
	w1 := &mockResponseWriter{}
	e.ProcessDNSQuery(w1, newTestQuery("aged.com"))
	if !isBlockedResponse(w1.msg) {
		t.Fatal("first sight should be blocked in block mode")
	}

	// After the window elapses, the same domain is no longer new -> forwarded.
	*cur = cur.Add(2 * time.Hour)
	w2 := &mockResponseWriter{}
	e.ProcessDNSQuery(w2, newTestQuery("aged.com"))
	if isBlockedResponse(w2.msg) {
		t.Error("domain past the NOD window should no longer be blocked")
	}
}
