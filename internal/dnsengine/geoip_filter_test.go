// SPDX-License-Identifier: GPL-3.0-or-later

package dnsengine

import (
	"net"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/geoip"
	"github.com/lopster568/phantomDNS/internal/threat"
	"github.com/miekg/dns"
)

// mockGeoResolver is a hermetic geoip.Resolver for engine-level tests.
type mockGeoResolver struct {
	asn     uint
	country string
}

func (m mockGeoResolver) Lookup(ip net.IP) (uint, string, error) {
	return m.asn, m.country, nil
}

// stubUpstream is a hermetic upstreamExchanger returning a canned answer, so
// the answer-filtering path runs without any network IO.
type stubUpstream struct {
	answer []dns.RR
	err    error
}

func newStubUpstream(rrs ...dns.RR) *stubUpstream {
	return &stubUpstream{answer: rrs}
}

func (s *stubUpstream) Exchange(q *dns.Msg, _ time.Duration, _ int) (*dns.Msg, error) {
	if s.err != nil {
		return nil, s.err
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = append(m.Answer, s.answer...)
	return m, nil
}

func (s *stubUpstream) Close() {}

func mustA(t *testing.T, rr string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(rr)
	if err != nil {
		t.Fatalf("failed to build RR %q: %v", rr, err)
	}
	return r
}

func TestAnswerIPs(t *testing.T) {
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{
		mustA(t, "example.com. 60 IN A 203.0.113.10"),
		mustA(t, "example.com. 60 IN AAAA 2001:db8::1"),
		mustA(t, "example.com. 60 IN CNAME alias.example.net."), // ignored
	}

	got := answerIPs(resp)
	if len(got) != 2 {
		t.Fatalf("expected 2 IPs (A + AAAA), got %d", len(got))
	}
	if got[0].String() != "203.0.113.10" {
		t.Errorf("expected first IP 203.0.113.10, got %s", got[0])
	}
	if got[1].String() != "2001:db8::1" {
		t.Errorf("expected second IP 2001:db8::1, got %s", got[1])
	}

	if answerIPs(nil) != nil {
		t.Error("expected nil for nil response")
	}
}

func TestEnrichThreat_EmptyResult(t *testing.T) {
	out := enrichThreat(threat.Result{}, "blocked ASN 64500")

	if !out.IsSuspicious {
		t.Error("expected IsSuspicious=true")
	}
	if out.DetectionMethod != "geoip" {
		t.Errorf("expected method geoip, got %q", out.DetectionMethod)
	}
	if out.Reason != "blocked ASN 64500" {
		t.Errorf("expected reason %q, got %q", "blocked ASN 64500", out.Reason)
	}
	if out.ThreatScore == 0 {
		t.Error("expected non-zero threat score")
	}
}

func TestEnrichThreat_PreservesExistingDetection(t *testing.T) {
	// An existing heuristic detection must not be overwritten by the GeoIP hit.
	existing := threat.Result{
		IsSuspicious:    true,
		ThreatScore:     0.9,
		DetectionMethod: "dga_hex",
		Reason:          "hexadecimal domain pattern",
	}
	out := enrichThreat(existing, "blocked country RU")

	if out.DetectionMethod != "dga_hex" {
		t.Errorf("expected existing method preserved, got %q", out.DetectionMethod)
	}
	if out.ThreatScore != 0.9 {
		t.Errorf("expected existing score preserved, got %v", out.ThreatScore)
	}
	if out.Reason != "hexadecimal domain pattern" {
		t.Errorf("expected existing reason preserved, got %q", out.Reason)
	}
}

func TestForwardUpstream_GeoBlockMode(t *testing.T) {
	// Block mode: an answer IP in a blocked ASN must yield a 0.0.0.0 block
	// response without forwarding the real answer. A stub upstream keeps this
	// hermetic (no network).
	e := newTestEngine(nil, nil)
	e.upstreamManager = newStubUpstream(mustA(t, "evil.com. 60 IN A 203.0.113.10"))
	e.geo = geoip.NewFilter(mockGeoResolver{asn: 64500, country: "RU"}, []uint{64500}, nil, true)

	w := &mockResponseWriter{}
	outcome := e.forwardUpstream(w, newTestQuery("evil.com"), "evil.com")

	if !outcome.geoMatched || !outcome.geoBlocked {
		t.Errorf("expected geo match+block, got %+v", outcome)
	}
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected blocked (0.0.0.0) response in GeoIP block mode, got %v", w.msg.Answer)
	}
}

func TestForwardUpstream_GeoFlagModeForwards(t *testing.T) {
	// Flag mode: the real answer is still returned even on a match.
	e := newTestEngine(nil, nil)
	e.upstreamManager = newStubUpstream(mustA(t, "cdn.com. 60 IN A 203.0.113.10"))
	e.geo = geoip.NewFilter(mockGeoResolver{asn: 64500, country: "RU"}, []uint{64500}, nil, false)

	w := &mockResponseWriter{}
	outcome := e.forwardUpstream(w, newTestQuery("cdn.com"), "cdn.com")

	if !outcome.geoMatched || outcome.geoBlocked {
		t.Errorf("expected geo match without block, got %+v", outcome)
	}
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if isBlockedResponse(w.msg) {
		t.Error("expected the real answer to be forwarded in flag mode, got a block")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer forwarded, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "203.0.113.10" {
		t.Errorf("expected forwarded A 203.0.113.10, got %v", w.msg.Answer[0])
	}
}

func TestForwardUpstream_GeoCleanAnswerPasses(t *testing.T) {
	e := newTestEngine(nil, nil)
	e.upstreamManager = newStubUpstream(mustA(t, "good.com. 60 IN A 192.0.2.5"))
	e.geo = geoip.NewFilter(mockGeoResolver{asn: 15169, country: "US"}, []uint{64500}, []string{"RU"}, true)

	w := &mockResponseWriter{}
	outcome := e.forwardUpstream(w, newTestQuery("good.com"), "good.com")

	if outcome.geoMatched {
		t.Errorf("expected no geo match for clean answer, got %+v", outcome)
	}
	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if isBlockedResponse(w.msg) {
		t.Error("expected clean answer to pass, got a block")
	}
}
