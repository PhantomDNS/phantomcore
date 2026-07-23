// SPDX-License-Identifier: GPL-3.0-or-later
package bundle

import (
	"strings"
	"testing"
)

func TestLoad_ParsesEmbeddedBundle(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) < 100 {
		t.Fatalf("expected a substantial bundle (>=100 domains), got %d", len(entries))
	}

	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		d := e.Domain
		if d == "" {
			t.Errorf("empty domain in bundle")
		}
		// Parser must have normalised: lowercase, no trailing dot, no IP prefix.
		if d != strings.ToLower(d) {
			t.Errorf("domain %q is not lowercased", d)
		}
		if strings.HasSuffix(d, ".") {
			t.Errorf("domain %q has trailing dot", d)
		}
		if strings.ContainsAny(d, " \t") {
			t.Errorf("domain %q contains whitespace (bad parse)", d)
		}
		if strings.HasPrefix(d, "0.0.0.0") || strings.HasPrefix(d, "127.0.0.1") {
			t.Errorf("domain %q still carries an IP prefix", d)
		}
		if seen[d] {
			t.Errorf("duplicate domain in bundle: %q", d)
		}
		seen[d] = true
	}

	// A few well-known entries that must be present in any sane default seed.
	mustContain := []string{
		"doubleclick.net",
		"google-analytics.com",
		"googlesyndication.com",
		"criteo.com",
		"coinhive.com",
	}
	for _, d := range mustContain {
		if !seen[d] {
			t.Errorf("expected bundle to contain %q", d)
		}
	}
}

func TestDomains_MatchesLoad(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	domains, err := Domains()
	if err != nil {
		t.Fatalf("Domains() error: %v", err)
	}
	if len(domains) != len(entries) {
		t.Fatalf("Domains() len %d != Load() len %d", len(domains), len(entries))
	}
	for i := range entries {
		if domains[i] != entries[i].Domain {
			t.Errorf("Domains()[%d]=%q != Load()[%d].Domain=%q", i, domains[i], i, entries[i].Domain)
		}
	}
}

func TestChecksum_StableAndNonEmpty(t *testing.T) {
	c1, err := Checksum()
	if err != nil {
		t.Fatalf("Checksum() error: %v", err)
	}
	if len(c1) != 64 { // hex SHA-256
		t.Fatalf("expected 64-char hex checksum, got %d chars", len(c1))
	}
	c2, _ := Checksum()
	if c1 != c2 {
		t.Errorf("Checksum() not stable: %q != %q", c1, c2)
	}
}
