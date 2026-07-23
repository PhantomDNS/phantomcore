// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseResolverScheme(t *testing.T) {
	tests := []struct {
		entry      string
		wantScheme string
		wantTarget string
		wantErr    bool
	}{
		{"1.1.1.1:53", schemePlain, "1.1.1.1:53", false},
		{"8.8.8.8:53", schemePlain, "8.8.8.8:53", false},
		{"udp://8.8.8.8:53", schemePlain, "8.8.8.8:53", false},
		{"tls://1.1.1.1:853", schemeDoT, "1.1.1.1:853", false},
		{"tls://dns.google", schemeDoT, "dns.google:853", false},
		{"TLS://1.1.1.1:853", schemeDoT, "1.1.1.1:853", false},
		{"https://cloudflare-dns.com/dns-query", schemeDoH, "https://cloudflare-dns.com/dns-query", false},
		{"  1.1.1.1:53  ", schemePlain, "1.1.1.1:53", false},
		{"", "", "", true},
		{"ftp://foo", "", "", true},
		{"tls://", "", "", true},
		{"udp://", "", "", true},
	}
	for _, tt := range tests {
		scheme, target, err := parseResolverScheme(tt.entry)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseResolverScheme(%q): expected error, got (%q, %q)", tt.entry, scheme, target)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseResolverScheme(%q): unexpected error %v", tt.entry, err)
			continue
		}
		if scheme != tt.wantScheme || target != tt.wantTarget {
			t.Errorf("parseResolverScheme(%q) = (%q, %q), want (%q, %q)",
				tt.entry, scheme, target, tt.wantScheme, tt.wantTarget)
		}
	}
}

func TestEnsurePort(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"1.1.1.1", "1.1.1.1:853"},
		{"1.1.1.1:853", "1.1.1.1:853"},
		{"dns.google", "dns.google:853"},
	}
	for _, tt := range tests {
		if got := ensurePort(tt.host, defaultDoTPort); got != tt.want {
			t.Errorf("ensurePort(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestNewUpstream_Encrypted(t *testing.T) {
	// DoT and DoH constructors must not touch the network, so this stays hermetic.
	up, err := newUpstream("tls://1.1.1.1:853", 4)
	if err != nil {
		t.Fatalf("newUpstream(tls): %v", err)
	}
	if _, ok := up.(*dotClient); !ok {
		t.Errorf("expected *dotClient, got %T", up)
	}

	up2, err := newUpstream("https://cloudflare-dns.com/dns-query", 4)
	if err != nil {
		t.Fatalf("newUpstream(https): %v", err)
	}
	if _, ok := up2.(*dohClient); !ok {
		t.Errorf("expected *dohClient, got %T", up2)
	}

	if _, err := newUpstream("ftp://nope", 4); err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestNewDoTClient(t *testing.T) {
	d, err := newDoTClient("1.1.1.1:853")
	if err != nil {
		t.Fatalf("newDoTClient: %v", err)
	}
	if d.client.Net != "tcp-tls" {
		t.Errorf("expected Net tcp-tls, got %q", d.client.Net)
	}
	if d.addr != "1.1.1.1:853" {
		t.Errorf("expected addr 1.1.1.1:853, got %q", d.addr)
	}
	if d.client.TLSConfig == nil || d.client.TLSConfig.ServerName != "1.1.1.1" {
		t.Errorf("expected TLS ServerName 1.1.1.1, got %+v", d.client.TLSConfig)
	}
	if got := d.Addr(); got != "tls://1.1.1.1:853" {
		t.Errorf("Addr() = %q, want tls://1.1.1.1:853", got)
	}
}

func TestNewDoTClient_MissingPort(t *testing.T) {
	if _, err := newDoTClient("1.1.1.1"); err == nil {
		t.Error("expected error for DoT address without a port")
	}
}

func TestNewDoHClient_Invalid(t *testing.T) {
	if _, err := newDoHClient("http://example.com/dns-query"); err == nil {
		t.Error("expected error for non-https DoH endpoint")
	}
	if _, err := newDoHClient("https://"); err == nil {
		t.Error("expected error for DoH endpoint without a host")
	}
}

func TestDoHExchange(t *testing.T) {
	const answerIP = "93.184.216.34"

	// A hermetic DoH server: unpack the wire-format request, verify the framing,
	// and respond with a valid dns-message reply.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != dohContentType {
			t.Errorf("expected Content-Type %q, got %q", dohContentType, ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		reqMsg := new(dns.Msg)
		if err := reqMsg.Unpack(body); err != nil {
			t.Fatalf("unpack request: %v", err)
		}
		if len(reqMsg.Question) != 1 || reqMsg.Question[0].Name != "example.com." {
			t.Fatalf("unexpected question in request: %+v", reqMsg.Question)
		}

		reply := new(dns.Msg)
		reply.SetReply(reqMsg)
		rr, err := dns.NewRR("example.com. 60 IN A " + answerIP)
		if err != nil {
			t.Fatalf("build RR: %v", err)
		}
		reply.Answer = append(reply.Answer, rr)

		packed, err := reply.Pack()
		if err != nil {
			t.Fatalf("pack reply: %v", err)
		}
		w.Header().Set("Content-Type", dohContentType)
		_, _ = w.Write(packed)
	}))
	defer srv.Close()

	d, err := newDoHClient(srv.URL)
	if err != nil {
		t.Fatalf("newDoHClient: %v", err)
	}
	// Trust the httptest server's self-signed certificate.
	d.client = srv.Client()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	resp, err := d.Exchange(q, time.Second)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %+v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if a.A.String() != answerIP {
		t.Errorf("expected %s, got %s", answerIP, a.A.String())
	}
	if resp.Id != q.Id {
		t.Errorf("response id %d != query id %d", resp.Id, q.Id)
	}
}

func TestDoHExchange_BadStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d, err := newDoHClient(srv.URL)
	if err != nil {
		t.Fatalf("newDoHClient: %v", err)
	}
	d.client = srv.Client()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	if _, err := d.Exchange(q, time.Second); err == nil {
		t.Error("expected error on non-200 status")
	}
}
