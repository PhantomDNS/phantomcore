package parser

import (
	"testing"
)

func TestHostsParser_Parse(t *testing.T) {
	input := []byte(`# This is a comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
::1 malware.example.com
# Another comment

0.0.0.0 UPPERCASE.COM.
192.168.1.1 should-be-skipped.com
invalid-line
0.0.0.0 last.entry.com
`)

	p := &HostsParser{}
	entries, err := p.Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"ads.example.com", "tracker.example.com", "malware.example.com", "uppercase.com", "last.entry.com"}
	if len(entries) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(entries))
	}
	for i, e := range entries {
		if e.Domain != want[i] {
			t.Errorf("entry[%d] = %q, want %q", i, e.Domain, want[i])
		}
	}
}

func TestHostsParser_SkipsComments(t *testing.T) {
	input := []byte("# only comments\n# here too\n")
	p := &HostsParser{}
	entries, err := p.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from comments-only input, got %d", len(entries))
	}
}

func TestHostsParser_EmptyInput(t *testing.T) {
	p := &HostsParser{}
	entries, err := p.Parse([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from empty input, got %d", len(entries))
	}
}

func TestHostsParser_Format(t *testing.T) {
	p := &HostsParser{}
	if got := p.Format(); got != "hosts" {
		t.Errorf("Format() = %q, want %q", got, "hosts")
	}
}

func TestRegistry_GetHosts(t *testing.T) {
	p, ok := Get("hosts")
	if !ok {
		t.Fatal("hosts parser not registered")
	}
	if p.Format() != "hosts" {
		t.Errorf("unexpected format: %s", p.Format())
	}
}

func TestRegistry_GetUnknown(t *testing.T) {
	_, ok := Get("nonexistent")
	if ok {
		t.Error("expected false for nonexistent parser")
	}
}

func TestDomainsParser_Parse(t *testing.T) {
	input := []byte(`# comment line
evil.com
Bad-Domain.NET.

*.wildcard.org
with.extra columns.here
; semicolon comment
   spaced.example.com
`)

	p := &DomainsParser{}
	entries, err := p.Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"evil.com", "bad-domain.net", "wildcard.org", "with.extra", "spaced.example.com"}
	if len(entries) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(entries))
	}
	for i, e := range entries {
		if e.Domain != want[i] {
			t.Errorf("entry[%d] = %q, want %q", i, e.Domain, want[i])
		}
	}
}

func TestDomainsParser_EmptyAndCommentsOnly(t *testing.T) {
	p := &DomainsParser{}
	for _, in := range [][]byte{[]byte(""), []byte("# only\n; comments\n\n")} {
		entries, err := p.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	}
}

func TestDomainsParser_Registered(t *testing.T) {
	p, ok := Get("domains")
	if !ok {
		t.Fatal("domains parser not registered")
	}
	if p.Format() != "domains" {
		t.Errorf("unexpected format: %s", p.Format())
	}
}
