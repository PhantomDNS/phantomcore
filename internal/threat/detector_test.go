package threat

import (
	"testing"
)

func TestDetector_NormalDomains(t *testing.T) {
	d := NewDetector()

	normal := []string{
		"google.com",
		"example.com",
		"stackoverflow.com",
		"en.wikipedia.org",
		"mail.google.com",
		"api.github.com",
	}

	for _, domain := range normal {
		r := d.Analyze(domain)
		if r.IsSuspicious {
			t.Errorf("normal domain %q flagged as suspicious: score=%.2f method=%s reason=%s",
				domain, r.ThreatScore, r.DetectionMethod, r.Reason)
		}
	}
}

func TestDetector_HexDGA(t *testing.T) {
	d := NewDetector()

	hex := []string{
		"a1b2c3d4e5f6a7b8.evil.com",
		"deadbeefcafebabe.malware.net",
	}

	for _, domain := range hex {
		r := d.Analyze(domain)
		if !r.IsSuspicious {
			t.Errorf("hex DGA domain %q not flagged", domain)
		}
		if r.DetectionMethod != "dga_hex" {
			t.Errorf("hex DGA domain %q: expected method dga_hex, got %s", domain, r.DetectionMethod)
		}
	}
}

func TestDetector_HighEntropy(t *testing.T) {
	d := NewDetector()

	// Random-looking domains
	suspicious := []string{
		"xkq7mz9plw2vb8nt.com",
		"r4nd0m5tr1ngd0m41n.net",
	}

	flagged := 0
	for _, domain := range suspicious {
		r := d.Analyze(domain)
		if r.IsSuspicious {
			flagged++
		}
	}
	if flagged == 0 {
		t.Error("no high-entropy domains were flagged")
	}
}

func TestDetector_LongDomain(t *testing.T) {
	d := NewDetector()

	long := "aaaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee.tunneling.com"
	r := d.Analyze(long)
	if !r.IsSuspicious {
		t.Errorf("long domain not flagged: %s", long)
	}
}

func TestDetector_DeepSubdomains(t *testing.T) {
	d := NewDetector()

	deep := "a.b.c.d.e.f.example.com"
	r := d.Analyze(deep)
	if !r.IsSuspicious {
		t.Error("deep subdomain not flagged")
	}
	if r.DetectionMethod != "subdomain_depth" {
		t.Errorf("expected subdomain_depth, got %s", r.DetectionMethod)
	}
}

func TestDetector_Typosquat_Flagged(t *testing.T) {
	d := NewDetectorWithBrands([]string{"paypal.com"})

	// xn--pypal-4ve.com decodes to "pаypal.com" where the second character is a
	// Cyrillic 'а' (U+0430) — a classic IDN homograph attack.
	cases := []string{
		"paypa1.com",        // digit '1' for 'l'
		"paypaI.com",        // capital 'I' for 'l'
		"paypall.com",       // inserted letter (edit distance 1)
		"payppal.com",       // doubled letter (edit distance 1)
		"xn--pypal-4ve.com", // punycode Cyrillic homograph
	}

	for _, domain := range cases {
		r := d.Analyze(domain)
		if !r.IsSuspicious {
			t.Errorf("typosquat %q not flagged", domain)
			continue
		}
		if r.DetectionMethod != "typosquat" {
			t.Errorf("typosquat %q: expected method typosquat, got %s", domain, r.DetectionMethod)
		}
		if r.Block {
			t.Errorf("typosquat %q: expected flag-only (Block=false) in default mode", domain)
		}
	}
}

func TestDetector_Typosquat_ExactBrandNotFlagged(t *testing.T) {
	d := NewDetectorWithBrands([]string{"paypal.com"})

	// The exact brand and its subdomains must never be flagged as typosquat.
	for _, domain := range []string{"paypal.com", "www.paypal.com", "api.paypal.com"} {
		r := d.Analyze(domain)
		if r.IsSuspicious && r.DetectionMethod == "typosquat" {
			t.Errorf("exact brand %q flagged as typosquat: %s", domain, r.Reason)
		}
	}
}

func TestDetector_Typosquat_UnrelatedNotFlagged(t *testing.T) {
	d := NewDetectorWithBrands([]string{"paypal.com"})

	for _, domain := range []string{"google.com", "example.com", "github.com", "amazon.com"} {
		r := d.Analyze(domain)
		if r.IsSuspicious && r.DetectionMethod == "typosquat" {
			t.Errorf("unrelated domain %q flagged as typosquat: %s", domain, r.Reason)
		}
	}
}

func TestDetector_Typosquat_EmptyWatchlistOff(t *testing.T) {
	// Default detector has no brands => typosquat detection is OFF.
	d := NewDetector()
	for _, domain := range []string{"paypa1.com", "paypaI.com", "xn--pypal-4ve.com"} {
		r := d.Analyze(domain)
		if r.DetectionMethod == "typosquat" {
			t.Errorf("empty watchlist should not run typosquat, but %q was flagged", domain)
		}
	}

	// Explicit empty/blank list is also OFF.
	d2 := NewDetectorWithBrands([]string{"", "  "})
	if r := d2.Analyze("paypa1.com"); r.DetectionMethod == "typosquat" {
		t.Error("blank watchlist entries should be ignored (feature OFF)")
	}
}

func TestDetector_Typosquat_BlockVsFlag(t *testing.T) {
	// Flag mode (default): suspicious but not marked to block.
	flag := NewDetectorWithBrands([]string{"paypal.com"})
	if r := flag.Analyze("paypa1.com"); !r.IsSuspicious || r.Block {
		t.Errorf("flag mode: want suspicious && !Block, got suspicious=%v block=%v", r.IsSuspicious, r.Block)
	}

	// Block mode: same hit, but marked to block.
	block := NewDetectorWithBrands([]string{"paypal.com"})
	block.SetTyposquatBlock(true)
	if r := block.Analyze("paypa1.com"); !r.IsSuspicious || !r.Block {
		t.Errorf("block mode: want suspicious && Block, got suspicious=%v block=%v", r.IsSuspicious, r.Block)
	}
	// Block mode must not affect non-typosquat traffic.
	if r := block.Analyze("google.com"); r.IsSuspicious {
		t.Errorf("block mode: unrelated domain flagged: %s", r.Reason)
	}
}

func TestShannonEntropy(t *testing.T) {
	// "aaaa" has 0 entropy
	e := shannonEntropy("aaaa")
	if e != 0 {
		t.Errorf("expected 0 entropy for 'aaaa', got %.2f", e)
	}

	// "abcd" has 2.0 entropy (4 equally frequent chars)
	e = shannonEntropy("abcd")
	if e < 1.9 || e > 2.1 {
		t.Errorf("expected ~2.0 entropy for 'abcd', got %.2f", e)
	}
}
