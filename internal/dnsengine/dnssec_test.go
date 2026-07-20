// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"github.com/miekg/dns"
)

const testZone = "example.com."

// baseTime is a fixed reference instant so signature validity windows are fully
// deterministic (no reliance on wall-clock time).
var baseTime = time.Unix(1_700_000_000, 0).UTC()

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse RR %q: %v", s, err)
	}
	return rr
}

// makeSignedFixture builds a signed A RRset for example.com using a freshly
// generated ECDSA P256 key. Fully hermetic: no network, no live resolver. The
// inception/expiration offsets are relative to baseTime so callers can craft
// expired or not-yet-valid vectors.
func makeSignedFixture(t *testing.T, inceptionOffset, expirationOffset time.Duration) (*dns.DNSKEY, []dns.RR, *dns.RRSIG) {
	t.Helper()

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: testZone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("private key does not implement crypto.Signer")
	}

	rrset := []dns.RR{mustRR(t, testZone+" 3600 IN A 93.184.216.34")}

	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: testZone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(testZone)),
		OrigTtl:     3600,
		Inception:   uint32(baseTime.Add(inceptionOffset).Unix()),
		Expiration:  uint32(baseTime.Add(expirationOffset).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  testZone,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("sign RRset: %v", err)
	}
	return key, rrset, sig
}

func msgWithAnswer(rrs ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = append(m.Answer, rrs...)
	return m
}

// --- Core validateRRSet tests (pure, no network) ---

func TestValidateRRSet_ValidSecure(t *testing.T) {
	key, rrset, sig := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	cs := coveredRRSet{name: testZone, rtype: dns.TypeA, rrset: rrset, rrsigs: []*dns.RRSIG{sig}}

	if got := validateRRSet(cs, []*dns.DNSKEY{key}, baseTime); got != StatusSecure {
		t.Fatalf("valid signature: want SECURE, got %s", got)
	}
}

func TestValidateRRSet_TamperedAnswerBogus(t *testing.T) {
	key, _, sig := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	// The answer the client would receive has been altered in transit; the RRSIG
	// no longer covers it.
	tampered := []dns.RR{mustRR(t, testZone+" 3600 IN A 6.6.6.6")}
	cs := coveredRRSet{name: testZone, rtype: dns.TypeA, rrset: tampered, rrsigs: []*dns.RRSIG{sig}}

	if got := validateRRSet(cs, []*dns.DNSKEY{key}, baseTime); got != StatusBogus {
		t.Fatalf("tampered answer: want BOGUS, got %s", got)
	}
}

func TestValidateRRSet_WrongKeyBogus(t *testing.T) {
	_, rrset, sig := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	// An unrelated key: its KeyTag will not match the RRSIG, so validation cannot
	// succeed.
	otherKey, _, _ := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	cs := coveredRRSet{name: testZone, rtype: dns.TypeA, rrset: rrset, rrsigs: []*dns.RRSIG{sig}}

	if got := validateRRSet(cs, []*dns.DNSKEY{otherKey}, baseTime); got != StatusBogus {
		t.Fatalf("wrong key: want BOGUS, got %s", got)
	}
}

func TestValidateRRSet_ExpiredBogus(t *testing.T) {
	// Signature expired one hour before baseTime.
	key, rrset, sig := makeSignedFixture(t, -48*time.Hour, -time.Hour)
	cs := coveredRRSet{name: testZone, rtype: dns.TypeA, rrset: rrset, rrsigs: []*dns.RRSIG{sig}}

	if got := validateRRSet(cs, []*dns.DNSKEY{key}, baseTime); got != StatusBogus {
		t.Fatalf("expired signature: want BOGUS, got %s", got)
	}
}

func TestValidateRRSet_UnsignedInsecure(t *testing.T) {
	rrset := []dns.RR{mustRR(t, testZone+" 3600 IN A 93.184.216.34")}
	cs := coveredRRSet{name: testZone, rtype: dns.TypeA, rrset: rrset}

	if got := validateRRSet(cs, nil, baseTime); got != StatusInsecure {
		t.Fatalf("unsigned RRset: want INSECURE, got %s", got)
	}
}

// --- classifyResponse tests (message-level, injected key fetcher) ---

func TestClassifyResponse_SecurePassthrough(t *testing.T) {
	key, rrset, sig := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	resp := msgWithAnswer(append(rrset, sig)...)
	fetch := func(string) ([]*dns.DNSKEY, error) { return []*dns.DNSKEY{key}, nil }

	if got := classifyResponse(resp, fetch, baseTime); got != StatusSecure {
		t.Fatalf("want SECURE, got %s", got)
	}
}

func TestClassifyResponse_BogusServfail(t *testing.T) {
	key, _, sig := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	tampered := mustRR(t, testZone+" 3600 IN A 6.6.6.6")
	resp := msgWithAnswer(tampered, sig)
	fetch := func(string) ([]*dns.DNSKEY, error) { return []*dns.DNSKEY{key}, nil }

	if got := classifyResponse(resp, fetch, baseTime); got != StatusBogus {
		t.Fatalf("tampered answer: want BOGUS, got %s", got)
	}
}

func TestClassifyResponse_UnsignedInsecure(t *testing.T) {
	resp := msgWithAnswer(mustRR(t, testZone+" 3600 IN A 1.2.3.4"))
	fetch := func(string) ([]*dns.DNSKEY, error) {
		t.Fatal("key fetch must not be called for an unsigned answer")
		return nil, nil
	}

	if got := classifyResponse(resp, fetch, baseTime); got != StatusInsecure {
		t.Fatalf("unsigned answer: want INSECURE, got %s", got)
	}
}

func TestClassifyResponse_KeyFetchFailSoftInsecure(t *testing.T) {
	_, rrset, sig := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	resp := msgWithAnswer(append(rrset, sig)...)
	fetch := func(string) ([]*dns.DNSKEY, error) { return nil, errors.New("DNSKEY fetch failed") }

	// Keys unavailable soft-fails to INSECURE (passthrough) rather than SERVFAIL,
	// so a partial validator cannot break resolution on a transient failure.
	if got := classifyResponse(resp, fetch, baseTime); got != StatusInsecure {
		t.Fatalf("key fetch failure: want INSECURE (soft-fail), got %s", got)
	}
}

func TestClassifyResponse_NilInsecure(t *testing.T) {
	if got := classifyResponse(nil, nil, baseTime); got != StatusInsecure {
		t.Fatalf("nil response: want INSECURE, got %s", got)
	}
}

// --- helpers: DO bit + DNSKEY extraction ---

func TestSetDO(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(testZone, dns.TypeA)

	setDO(m)
	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("expected an OPT record after setDO")
	}
	if !opt.Do() {
		t.Fatal("expected DO bit to be set")
	}

	// Idempotent: calling again keeps the DO bit set and does not add a second OPT.
	setDO(m)
	if !m.IsEdns0().Do() {
		t.Fatal("DO bit lost after second setDO")
	}
	if len(m.Extra) != 1 {
		t.Fatalf("expected exactly one OPT record, got %d Extra RRs", len(m.Extra))
	}
}

func TestExtractDNSKEYs(t *testing.T) {
	key, _, _ := makeSignedFixture(t, -time.Hour, 24*time.Hour)
	resp := msgWithAnswer(key, mustRR(t, testZone+" 3600 IN A 1.2.3.4"))

	keys := extractDNSKEYs(resp)
	if len(keys) != 1 {
		t.Fatalf("expected 1 DNSKEY, got %d", len(keys))
	}
	if extractDNSKEYs(nil) != nil {
		t.Fatal("expected nil for nil response")
	}
}

// --- engine wiring: default OFF, opt-in ON ---

func TestNewDNSEngine_DNSSECDefaultOff(t *testing.T) {
	repos := &repositories.Store{}
	pe := policy.NewPolicyEngine()
	// No DNSSECValidation set -> zero value false.
	cfg := config.DataPlaneConfig{UpstreamResolvers: []string{"127.0.0.1:53"}}

	e, err := NewDNSEngine(cfg, repos, pe)
	if err != nil {
		t.Fatalf("NewDNSEngine: %v", err)
	}
	defer e.Shutdown()

	if e.dnssecEnabled {
		t.Fatal("DNSSEC validation must default to OFF")
	}
}

func TestNewDNSEngine_DNSSECOptIn(t *testing.T) {
	repos := &repositories.Store{}
	pe := policy.NewPolicyEngine()
	cfg := config.DataPlaneConfig{
		UpstreamResolvers: []string{"127.0.0.1:53"},
		DNSSECValidation:  true,
	}

	e, err := NewDNSEngine(cfg, repos, pe)
	if err != nil {
		t.Fatalf("NewDNSEngine: %v", err)
	}
	defer e.Shutdown()

	if !e.dnssecEnabled {
		t.Fatal("DNSSEC validation must be ON when opted in")
	}
}
