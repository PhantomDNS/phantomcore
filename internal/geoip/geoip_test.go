// SPDX-License-Identifier: GPL-3.0-or-later

package geoip

import (
	"errors"
	"net"
	"testing"
)

// mockResolver is a hermetic Resolver: it returns canned ASN/country data from
// a table keyed by IP string, so tests never touch a real .mmdb file.
type mockResolver struct {
	table map[string]struct {
		asn     uint
		country string
	}
	err error
}

func (m *mockResolver) Lookup(ip net.IP) (uint, string, error) {
	if m.err != nil {
		return 0, "", m.err
	}
	if rec, ok := m.table[ip.String()]; ok {
		return rec.asn, rec.country, nil
	}
	// Unknown IP: MaxMind returns the zero record without an error.
	return 0, "", nil
}

func newMockResolver() *mockResolver {
	return &mockResolver{
		table: map[string]struct {
			asn     uint
			country string
		}{
			"203.0.113.10": {asn: 64500, country: "RU"}, // blocked ASN
			"198.51.100.7": {asn: 12345, country: "CN"}, // blocked country
			"192.0.2.5":    {asn: 15169, country: "US"}, // clean (Google-ish)
		},
	}
}

func ips(list ...string) []net.IP {
	out := make([]net.IP, 0, len(list))
	for _, s := range list {
		out = append(out, net.ParseIP(s))
	}
	return out
}

func TestFilter_BlockedASN_FlagMode(t *testing.T) {
	f := NewFilter(newMockResolver(), []uint{64500}, nil, false)
	if f == nil {
		t.Fatal("expected non-nil filter")
	}

	d := f.Evaluate(ips("203.0.113.10"))
	if !d.Matched {
		t.Fatal("expected match on blocked ASN")
	}
	if d.Block {
		t.Error("expected flag-only decision (Block=false) in flag mode")
	}
	if d.ASN != 64500 {
		t.Errorf("expected ASN 64500, got %d", d.ASN)
	}
	if f.BlockMode() {
		t.Error("expected BlockMode()=false in flag mode")
	}
}

func TestFilter_BlockedASN_BlockMode(t *testing.T) {
	f := NewFilter(newMockResolver(), []uint{64500}, nil, true)

	d := f.Evaluate(ips("203.0.113.10"))
	if !d.Matched {
		t.Fatal("expected match on blocked ASN")
	}
	if !d.Block {
		t.Error("expected block decision (Block=true) in block mode")
	}
	if !f.BlockMode() {
		t.Error("expected BlockMode()=true in block mode")
	}
}

func TestFilter_BlockedCountry(t *testing.T) {
	// Lower-case config value must still match the resolver's upper-case code.
	f := NewFilter(newMockResolver(), nil, []string{"cn"}, true)

	d := f.Evaluate(ips("198.51.100.7"))
	if !d.Matched {
		t.Fatal("expected match on blocked country")
	}
	if d.Country != "CN" {
		t.Errorf("expected country CN, got %q", d.Country)
	}
	if d.ASN != 0 {
		t.Errorf("expected ASN 0 for a country match, got %d", d.ASN)
	}
}

func TestFilter_AllowedPasses(t *testing.T) {
	f := NewFilter(newMockResolver(), []uint{64500}, []string{"RU"}, true)

	d := f.Evaluate(ips("192.0.2.5")) // US / ASN 15169, neither blocked
	if d.Matched {
		t.Errorf("expected clean IP to pass, got match: %+v", d)
	}
}

func TestFilter_FirstMatchAcrossMultipleIPs(t *testing.T) {
	f := NewFilter(newMockResolver(), []uint{64500}, nil, true)

	// Clean IP first, offending IP second — must still match.
	d := f.Evaluate(ips("192.0.2.5", "203.0.113.10"))
	if !d.Matched {
		t.Fatal("expected match when a later answer IP is in a blocked ASN")
	}
	if d.IP != "203.0.113.10" {
		t.Errorf("expected offending IP 203.0.113.10, got %q", d.IP)
	}
}

func TestFilter_NoDBInert(t *testing.T) {
	// No resolver => nil filter => inert. FromConfig("") is the real-world path.
	f, err := FromConfig("", []uint{64500}, []string{"RU"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != nil {
		t.Fatal("expected nil filter when no DB path is configured")
	}

	// A nil filter must be safe to call and never match.
	if f.BlockMode() {
		t.Error("nil filter BlockMode() should be false")
	}
	if d := f.Evaluate(ips("203.0.113.10")); d.Matched {
		t.Error("nil filter must never match")
	}
}

func TestFilter_NoBlockListsInert(t *testing.T) {
	// A resolver with empty block lists has nothing to enforce.
	if f := NewFilter(newMockResolver(), nil, nil, true); f != nil {
		t.Error("expected nil filter when no ASNs or countries are blocked")
	}
	// Blank/whitespace country entries are ignored, leaving nothing to enforce.
	if f := NewFilter(newMockResolver(), nil, []string{"", "  "}, true); f != nil {
		t.Error("expected nil filter when only blank countries are configured")
	}
}

func TestFilter_LookupErrorSkipped(t *testing.T) {
	// A lookup error must be treated as a miss (fail-open on the allow path).
	r := &mockResolver{err: errors.New("db read failed")}
	f := NewFilter(r, []uint{64500}, []string{"RU"}, true)

	if d := f.Evaluate(ips("203.0.113.10")); d.Matched {
		t.Error("lookup error should be skipped, not matched")
	}
}

func TestFilter_EmptyAndNilIPs(t *testing.T) {
	f := NewFilter(newMockResolver(), []uint{64500}, nil, true)

	if d := f.Evaluate(nil); d.Matched {
		t.Error("nil IP list should not match")
	}
	if d := f.Evaluate([]net.IP{nil}); d.Matched {
		t.Error("nil IP entry should be skipped")
	}
}

func TestFilter_UnknownASNZeroNeverMatches(t *testing.T) {
	// Configuring ASN 0 must not cause unknown IPs (which resolve to ASN 0) to
	// match, otherwise every unresolved answer would be blocked.
	f := NewFilter(newMockResolver(), []uint{0}, nil, true)

	if d := f.Evaluate(ips("10.10.10.10")); d.Matched { // not in mock table
		t.Error("unknown IP (ASN 0) must never match a blocked ASN 0")
	}
}
