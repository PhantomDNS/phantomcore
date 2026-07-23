// SPDX-License-Identifier: GPL-3.0-or-later
package nrd

import "testing"

func TestSet_Contains(t *testing.T) {
	s := NewSet([]string{"evil.com", "bad-domain.net", "Newly.Registered.IO."})

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"exact match", "evil.com", true},
		{"parent-domain match", "login.evil.com", true},
		{"deep parent-domain match", "a.b.c.evil.com", true},
		{"fqdn trailing dot", "evil.com.", true},
		{"uppercase query normalized", "EVIL.COM", true},
		{"listed entry normalized on load", "newly.registered.io", true},
		{"not in set", "good.com", false},
		{"tld only is never a match", "com", false},
		{"sibling not matched", "notevil.com", false},
		{"empty query", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Contains(tt.domain); got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestSet_Empty_Inert(t *testing.T) {
	empty := NewSet(nil)
	if empty.Len() != 0 {
		t.Fatalf("expected empty set, got len %d", empty.Len())
	}
	if empty.Contains("anything.com") {
		t.Error("empty set must match nothing")
	}
}

func TestSet_Nil(t *testing.T) {
	var s *Set
	if s.Len() != 0 {
		t.Errorf("nil set Len = %d, want 0", s.Len())
	}
	if s.Contains("evil.com") {
		t.Error("nil set must match nothing")
	}
}

func TestSet_DeduplicatesAndDropsBlanks(t *testing.T) {
	s := NewSet([]string{"evil.com", "EVIL.COM", "evil.com.", "  ", ""})
	if s.Len() != 1 {
		t.Errorf("expected 1 unique domain, got %d", s.Len())
	}
}

func TestChecker_NoFeed_Inert(t *testing.T) {
	c := New(Config{}) // no FeedURL
	if c.Enabled() {
		t.Error("checker with no feed URL must not be enabled")
	}
	if c.IsListed("evil.com") {
		t.Error("checker with no loaded feed must be inert")
	}
	if c.BlockMode() {
		t.Error("default checker must be flag mode (BlockMode=false)")
	}
	if c.Len() != 0 {
		t.Errorf("expected 0 loaded domains, got %d", c.Len())
	}
}

func TestChecker_Defaults(t *testing.T) {
	c := New(Config{FeedURL: "https://example.test/nrd.txt"})
	if !c.Enabled() {
		t.Error("checker with feed URL must be enabled")
	}
	if c.cfg.RefreshInterval != defaultRefreshInterval {
		t.Errorf("RefreshInterval = %v, want default %v", c.cfg.RefreshInterval, defaultRefreshInterval)
	}
	if c.cfg.Format != defaultFormat {
		t.Errorf("Format = %q, want default %q", c.cfg.Format, defaultFormat)
	}
}

func TestChecker_BlockVsFlag(t *testing.T) {
	block := NewWithSet(NewSet([]string{"evil.com"}), true)
	if !block.BlockMode() {
		t.Error("expected BlockMode=true")
	}
	if !block.IsListed("evil.com") {
		t.Error("expected evil.com listed in block-mode checker")
	}

	flag := NewWithSet(NewSet([]string{"evil.com"}), false)
	if flag.BlockMode() {
		t.Error("expected BlockMode=false (flag)")
	}
	if !flag.IsListed("sub.evil.com") {
		t.Error("expected parent-domain match in flag-mode checker")
	}
}

func TestChecker_LoadFeed(t *testing.T) {
	feed := []byte(`# newly registered domains
evil.com
bad.net

*.wildcard.org
notes.example.io   2026-07-19
; semicolon comment
`)
	c := New(Config{FeedURL: "https://example.test/nrd.txt"}) // format defaults to "domains"
	if err := c.load(feed); err != nil {
		t.Fatalf("load feed: %v", err)
	}

	if got, want := c.Len(), 4; got != want {
		t.Fatalf("loaded %d domains, want %d", got, want)
	}
	for _, d := range []string{"evil.com", "bad.net", "wildcard.org", "notes.example.io"} {
		if !c.IsListed(d) {
			t.Errorf("expected %q to be listed after load", d)
		}
	}
	// Parent match through a loaded feed entry.
	if !c.IsListed("mail.evil.com") {
		t.Error("expected parent-domain match for mail.evil.com")
	}
	if c.IsListed("clean.com") {
		t.Error("unlisted domain must not match")
	}
}

func TestChecker_LoadFeed_ReplacesSet(t *testing.T) {
	c := New(Config{FeedURL: "https://example.test/nrd.txt"})
	if err := c.load([]byte("first.com\n")); err != nil {
		t.Fatal(err)
	}
	if !c.IsListed("first.com") {
		t.Fatal("first.com should be listed after initial load")
	}
	if err := c.load([]byte("second.com\n")); err != nil {
		t.Fatal(err)
	}
	if c.IsListed("first.com") {
		t.Error("first.com should be gone after set replacement")
	}
	if !c.IsListed("second.com") {
		t.Error("second.com should be listed after replacement")
	}
}

func TestChecker_Nil(t *testing.T) {
	var c *Checker
	if c.Enabled() || c.BlockMode() || c.IsListed("evil.com") || c.Len() != 0 {
		t.Error("nil checker must be fully inert")
	}
}
