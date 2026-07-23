// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"math/rand"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// randomizeCase must only change the case of ASCII letters: the result is
// case-insensitively equal to the input and every non-letter byte (digits,
// dots, hyphens, ...) is preserved in place.
func TestRandomizeCase_PreservesNonLetters(t *testing.T) {
	names := []string{
		"foo-bar123.example-9.com.",
		"a1b2c3.test-domain.io.",
		"192-0-2-1.in-addr.arpa.",
		"",
	}
	for _, name := range names {
		for seed := int64(0); seed < 20; seed++ {
			r := rand.New(rand.NewSource(seed))
			got := randomizeCase(name, r)

			if len(got) != len(name) {
				t.Fatalf("randomizeCase(%q) changed length: %q", name, got)
			}
			if !strings.EqualFold(got, name) {
				t.Fatalf("randomizeCase(%q)=%q is not case-insensitively equal", name, got)
			}
			for i := 0; i < len(name); i++ {
				oc := name[i]
				isLetter := (oc >= 'a' && oc <= 'z') || (oc >= 'A' && oc <= 'Z')
				if !isLetter && got[i] != oc {
					t.Errorf("randomizeCase(%q) changed non-letter at %d: %q -> %q", name, i, string(oc), string(got[i]))
				}
			}
		}
	}
}

// The same seed must yield the same output (needed for deterministic behaviour).
func TestRandomizeCase_DeterministicSeed(t *testing.T) {
	a := randomizeCase("secure.example.com.", rand.New(rand.NewSource(42)))
	b := randomizeCase("secure.example.com.", rand.New(rand.NewSource(42)))
	if a != b {
		t.Fatalf("same seed produced different output: %q vs %q", a, b)
	}
}

// Over enough seeds, a many-letter name must actually get some letters flipped,
// otherwise the encoding would add no entropy.
func TestRandomizeCase_FlipsSomeLetters(t *testing.T) {
	const name = "abcdefghijklmnop.example.com."
	changed := false
	for seed := int64(0); seed < 50 && !changed; seed++ {
		if randomizeCase(name, rand.New(rand.NewSource(seed))) != name {
			changed = true
		}
	}
	if !changed {
		t.Fatal("randomizeCase never changed a many-letter name across 50 seeds")
	}
}

func TestEqualNameFold(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com.", "ExAmPlE.CoM.", true},
		{"example.com.", "example.com.", true},
		{"EXAMPLE.COM.", "example.com.", true},
		{"example.com.", "example.net.", false},
		{"a.com.", "b.com.", false},
	}
	for _, c := range cases {
		if got := equalNameFold(c.a, c.b); got != c.want {
			t.Errorf("equalNameFold(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// With 0x20 disabled the outbound path must be unchanged: the exact same
// message pointer is returned and no originals are captured (no network here).
func TestPrepareOutbound_DisabledUnchanged(t *testing.T) {
	m := &UpstreamManager{dns0x20: false}
	q := new(dns.Msg)
	q.SetQuestion("ExAmPlE.CoM.", dns.TypeA)

	out, originals := m.prepareOutbound(q, nil)
	if out != q {
		t.Error("disabled 0x20 must return the original message unchanged (same pointer)")
	}
	if originals != nil {
		t.Errorf("disabled 0x20 must return nil originals, got %v", originals)
	}
	if q.Question[0].Name != "ExAmPlE.CoM." {
		t.Errorf("query must not be mutated while disabled, got %q", q.Question[0].Name)
	}
}

// With 0x20 enabled a randomized copy is sent, the original name is captured,
// and the caller's message is left untouched.
func TestPrepareOutbound_EnabledRandomizes(t *testing.T) {
	m := &UpstreamManager{dns0x20: true}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r := rand.New(rand.NewSource(1))

	out, originals := m.prepareOutbound(q, r)
	if out == q {
		t.Fatal("enabled 0x20 must send a copy, not the original message")
	}
	if len(originals) != 1 || originals[0] != "example.com." {
		t.Fatalf("originals not captured correctly: %v", originals)
	}
	if !equalNameFold(out.Question[0].Name, "example.com.") {
		t.Errorf("outbound qname %q not case-insensitively equal to original", out.Question[0].Name)
	}
	if q.Question[0].Name != "example.com." {
		t.Errorf("original query must not be mutated, got %q", q.Question[0].Name)
	}
}

// restoreCase0x20 restores the client's requested case in the question and in
// RR owner names that match the question name, while leaving unrelated names
// (a CNAME target, an A record for a different owner) untouched.
func TestRestoreCase0x20_RestoresOriginalCase(t *testing.T) {
	resp := new(dns.Msg)
	resp.Question = []dns.Question{{Name: "eXAmPLe.CoM.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	resp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "eXAmPLe.CoM.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "cdn.example.net.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "cdn.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		},
	}

	restoreCase0x20(resp, []string{"example.com."})

	if resp.Question[0].Name != "example.com." {
		t.Errorf("question name not restored: %q", resp.Question[0].Name)
	}
	if got := resp.Answer[0].Header().Name; got != "example.com." {
		t.Errorf("matching owner name not restored: %q", got)
	}
	if tgt := resp.Answer[0].(*dns.CNAME).Target; tgt != "cdn.example.net." {
		t.Errorf("CNAME target should be untouched, got %q", tgt)
	}
	if got := resp.Answer[1].Header().Name; got != "cdn.example.net." {
		t.Errorf("non-matching owner name should be untouched, got %q", got)
	}
}

// A question that does not fold to the sent name (a spoof-like mismatch) must
// not be rewritten.
func TestRestoreCase0x20_MismatchLeftUntouched(t *testing.T) {
	resp := new(dns.Msg)
	resp.Question = []dns.Question{{Name: "attacker.evil.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}

	restoreCase0x20(resp, []string{"example.com."})

	if resp.Question[0].Name != "attacker.evil.com." {
		t.Errorf("mismatched question name should be left untouched, got %q", resp.Question[0].Name)
	}
}

func TestRestoreCase0x20_NilSafe(t *testing.T) {
	restoreCase0x20(nil, []string{"example.com."}) // must not panic
}
