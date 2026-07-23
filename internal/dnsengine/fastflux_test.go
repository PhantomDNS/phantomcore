// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeClock (deterministic, manually-advanced) is defined once for the
// package in ratelimit_test.go and reused here. No real sleeps are used
// anywhere in this file.

// trackedDomainCount / trackedIPCount are test-only introspection helpers,
// defined here (same package) so production code carries no test hooks.
func (t *fastFluxTracker) trackedDomainCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.domains)
}

func (t *fastFluxTracker) trackedIPCount(domain string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.domains[domain]
	if e == nil {
		return 0
	}
	return len(e.ips)
}

// ip is a tiny helper to build a distinct IPv4 for index i (1..254 per octet).
func ip(i int) net.IP {
	return net.IPv4(10, byte(i/256), byte(i%256), 1)
}

func distinctIPs(n int) []net.IP {
	out := make([]net.IP, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ip(i))
	}
	return out
}

func TestFastFlux_TripsOnManyDistinctLowTTLIPs(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	tr := newFastFluxTracker(8, 300, 5*time.Minute, 1024, clk.now)

	// Feed 7 distinct IPs one at a time with a low TTL: below the threshold.
	for i := 0; i < 7; i++ {
		if tr.observe("flux.example.com", []net.IP{ip(i)}, 60) {
			t.Fatalf("tripped early at %d distinct IPs (threshold 8)", i+1)
		}
		clk.advance(time.Second)
	}

	// The 8th distinct IP reaches the threshold with TTL 60 <= 300 -> trip.
	if !tr.observe("flux.example.com", []net.IP{ip(7)}, 60) {
		t.Fatal("expected fast-flux trip at 8 distinct low-TTL IPs")
	}
}

func TestFastFlux_TripsOnSingleAnswerWithManyIPs(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	tr := newFastFluxTracker(8, 300, 5*time.Minute, 1024, clk.now)

	// A single answer carrying 10 distinct low-TTL IPs should trip immediately.
	if !tr.observe("flux.example.com", distinctIPs(10), 30) {
		t.Fatal("expected trip on a single answer with 10 distinct low-TTL IPs")
	}
}

func TestFastFlux_StableDomainDoesNotTrip(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	tr := newFastFluxTracker(8, 300, 5*time.Minute, 1024, clk.now)

	// A stable domain returns the same 2 IPs many times with a low TTL. Distinct
	// count stays at 2, well under the threshold: never trips.
	stable := []net.IP{ip(1), ip(2)}
	for i := 0; i < 50; i++ {
		if tr.observe("stable.example.com", stable, 60) {
			t.Fatalf("stable domain (2 distinct IPs) tripped on iteration %d", i)
		}
		clk.advance(2 * time.Second)
	}
}

func TestFastFlux_HighTTLDoesNotTrip(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	tr := newFastFluxTracker(8, 300, 5*time.Minute, 1024, clk.now)

	// 12 distinct IPs (over the count threshold) but a high TTL (3600 > 300).
	// The TTL condition fails, so it must not trip.
	if tr.observe("slowcdn.example.com", distinctIPs(12), 3600) {
		t.Fatal("high-TTL domain should not trip even with many distinct IPs")
	}
}

func TestFastFlux_DisabledNilTrackerIsOff(t *testing.T) {
	var tr *fastFluxTracker // nil == disabled (default)
	if tr.observe("anything.example.com", distinctIPs(50), 1) {
		t.Fatal("nil tracker (disabled) must never trip")
	}
}

func TestFastFlux_WindowExpiryDropsOldIPs(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	window := 5 * time.Minute
	tr := newFastFluxTracker(8, 300, window, 1024, clk.now)

	// Seed 7 distinct IPs within the window (still below threshold).
	if tr.observe("flux.example.com", distinctIPs(7), 60) {
		t.Fatal("did not expect trip with only 7 distinct IPs")
	}

	// Advance past the window, then observe 1 fresh IP. The 7 old IPs must be
	// pruned, leaving only the fresh one -> no trip.
	clk.advance(window + time.Minute)
	if tr.observe("flux.example.com", []net.IP{ip(100)}, 60) {
		t.Fatal("expired IPs should have been dropped; single fresh IP must not trip")
	}
	if got := tr.trackedIPCount("flux.example.com"); got != 1 {
		t.Fatalf("expected 1 live IP after window expiry, got %d", got)
	}

	// Now add 7 more fresh distinct IPs within the window -> 8 fresh total -> trip.
	if !tr.observe("flux.example.com", distinctIPs(7), 60) {
		t.Fatal("expected trip once 8 fresh distinct IPs are within the window")
	}
}

func TestFastFlux_BoundedMemoryEvictsDomains(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	const cap = 3
	tr := newFastFluxTracker(8, 300, 5*time.Minute, cap, clk.now)

	// Observe far more distinct domains than the cap; each keeps a live IP.
	for i := 0; i < 20; i++ {
		tr.observe(fmt.Sprintf("d%d.example.com", i), []net.IP{ip(i)}, 60)
		clk.advance(time.Second) // distinct lastSeen for deterministic eviction
	}

	if got := tr.trackedDomainCount(); got > cap {
		t.Fatalf("tracked domains %d exceeds cap %d", got, cap)
	}
}

func TestExtractAnswerIPs(t *testing.T) {
	msg := new(dns.Msg)
	a1, _ := dns.NewRR("flux.example.com. 45 IN A 1.2.3.4")
	a2, _ := dns.NewRR("flux.example.com. 30 IN A 5.6.7.8")
	aaaa, _ := dns.NewRR("flux.example.com. 90 IN AAAA ::1")
	cname, _ := dns.NewRR("flux.example.com. 300 IN CNAME other.example.com.")
	msg.Answer = []dns.RR{cname, a1, a2, aaaa}

	ips, minTTL, ok := extractAnswerIPs(msg)
	if !ok {
		t.Fatal("expected ok with A/AAAA records present")
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 address records (CNAME ignored), got %d", len(ips))
	}
	if minTTL != 30 {
		t.Fatalf("expected min TTL 30, got %d", minTTL)
	}

	// No address records -> ok=false.
	only := new(dns.Msg)
	only.Answer = []dns.RR{cname}
	if _, _, ok := extractAnswerIPs(only); ok {
		t.Fatal("expected ok=false when no A/AAAA records present")
	}

	if _, _, ok := extractAnswerIPs(nil); ok {
		t.Fatal("expected ok=false for nil response")
	}
}
