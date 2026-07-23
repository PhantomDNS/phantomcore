// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{
		Timestamp:       time.Date(2026, 7, 20, 12, 30, 0, 0, time.UTC),
		Domain:          "evil.com",
		ClientIP:        "10.0.0.1:5353",
		Action:          "block",
		IsSuspicious:    true,
		ThreatScore:     0.95,
		DetectionMethod: "entropy",
		ThreatReason:    "high entropy",
	}
}

func TestSeverityFor(t *testing.T) {
	cases := map[string]int{
		"allow":    6,
		"flagged":  4,
		"block":    5,
		"redirect": 5,
		"error":    3,
		"unknown":  6,
	}
	for action, want := range cases {
		if got := severityFor(action); got != want {
			t.Errorf("severityFor(%q) = %d, want %d", action, got, want)
		}
	}
}

func TestEscapeSD(t *testing.T) {
	// RFC 5424 requires escaping of '"', '\' and ']' inside PARAM-VALUE.
	in := `a"b\c]d`
	want := `a\"b\\c\]d`
	if got := escapeSD(in); got != want {
		t.Errorf("escapeSD(%q) = %q, want %q", in, got, want)
	}
}

func TestFormatRFC5424(t *testing.T) {
	ev := sampleEvent()
	line := formatRFC5424("box-1", "hydradns", "42", ev.Timestamp, ev)

	// PRI = facility(local0=16)*8 + severity(block=5) = 133, version 1.
	if !strings.HasPrefix(line, "<133>1 ") {
		t.Errorf("expected PRI/version prefix <133>1, got line: %s", line)
	}

	wantSubstrings := []string{
		"2026-07-20T12:30:00Z",         // RFC3339 timestamp
		" box-1 hydradns 42 DNSQUERY ", // HOSTNAME APP-NAME PROCID MSGID
		"[hydradns@32473 ",             // structured-data element id
		`domain="evil.com"`,
		`client="10.0.0.1:5353"`,
		`action="block"`,
		`suspicious="true"`,
		`score="0.95"`,
		`method="entropy"`,
		`reason="high entropy"`,
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(line, s) {
			t.Errorf("RFC5424 line missing %q\nline: %s", s, line)
		}
	}
}

func TestFormatRFC5424_NilFieldsAndZeroTime(t *testing.T) {
	// Empty header fields must render as the RFC nil value "-".
	ev := Event{Action: "allow"} // zero timestamp
	line := formatRFC5424("", "", "", ev.Timestamp, ev)

	// PRI = 16*8 + 6 (allow) = 134.
	if !strings.HasPrefix(line, "<134>1 - - - - DNSQUERY ") {
		t.Errorf("expected nil header fields, got: %s", line)
	}
}

func TestFormatRFC5424_EscapesStructuredData(t *testing.T) {
	ev := sampleEvent()
	ev.ThreatReason = `bad "quote" and ] bracket`
	line := formatRFC5424("h", "a", "1", ev.Timestamp, ev)
	if !strings.Contains(line, `reason="bad \"quote\" and \] bracket"`) {
		t.Errorf("structured-data value not escaped: %s", line)
	}
}

func TestParseSyslogAddr(t *testing.T) {
	cases := []struct {
		in       string
		wantNet  string
		wantAddr string
		wantErr  bool
	}{
		{"udp://host:514", "udp", "host:514", false},
		{"tcp://1.2.3.4:601", "tcp", "1.2.3.4:601", false},
		{"host:514", "udp", "host:514", false}, // bare defaults to udp
		{"http://host:514", "", "", true},      // unsupported network
		{"", "", "", true},                     // empty
	}
	for _, c := range cases {
		gotNet, gotAddr, err := parseSyslogAddr(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseSyslogAddr(%q) expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSyslogAddr(%q) unexpected error: %v", c.in, err)
			continue
		}
		if gotNet != c.wantNet || gotAddr != c.wantAddr {
			t.Errorf("parseSyslogAddr(%q) = (%q,%q), want (%q,%q)", c.in, gotNet, gotAddr, c.wantNet, c.wantAddr)
		}
	}
}

func TestWebhookSink_Send_PostsValidJSON(t *testing.T) {
	type received struct {
		contentType string
		body        []byte
	}
	got := make(chan received, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		got <- received{contentType: r.Header.Get("Content-Type"), body: b}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := newWebhookSink(srv.URL)
	ev := sampleEvent()
	if err := sink.Send(ev); err != nil {
		t.Fatalf("webhook Send failed: %v", err)
	}

	select {
	case r := <-got:
		if r.contentType != "application/json" {
			t.Errorf("expected application/json, got %q", r.contentType)
		}
		var decoded Event
		if err := json.Unmarshal(r.body, &decoded); err != nil {
			t.Fatalf("webhook body is not valid JSON: %v (body=%s)", err, r.body)
		}
		if decoded.Domain != ev.Domain || decoded.Action != ev.Action || decoded.ThreatScore != ev.ThreatScore {
			t.Errorf("decoded event mismatch: %+v", decoded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook server did not receive request")
	}
}

func TestWebhookSink_Send_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := newWebhookSink(srv.URL)
	if err := sink.Send(sampleEvent()); err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

func TestNewExporter_DisabledIsNil(t *testing.T) {
	exp, err := NewExporter("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp != nil {
		t.Fatal("expected nil exporter when both targets are empty")
	}
	// nil exporter must be a safe no-op.
	exp.Export(sampleEvent())
	exp.Close()
	if exp.Dropped() != 0 {
		t.Errorf("expected 0 dropped on nil exporter, got %d", exp.Dropped())
	}
}

func TestExporter_DropsWhenFullWithoutBlocking(t *testing.T) {
	// White-box: build an exporter with a tiny queue and NO running worker,
	// so nothing drains it. Export must never block and must drop overflow.
	exp := &Exporter{queue: make(chan Event, 2)}

	const total = 10
	done := make(chan struct{})
	go func() {
		for i := 0; i < total; i++ {
			exp.Export(sampleEvent())
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Export blocked when queue was full")
	}

	// 2 fit in the buffer, the remaining 8 are dropped.
	if got := exp.Dropped(); got != total-2 {
		t.Errorf("expected %d drops, got %d", total-2, got)
	}
}

func TestExporter_WebhookEndToEnd(t *testing.T) {
	got := make(chan Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Event
		_ = json.NewDecoder(r.Body).Decode(&ev)
		got <- ev
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp, err := NewExporter("", srv.URL)
	if err != nil {
		t.Fatalf("NewExporter error: %v", err)
	}
	if exp == nil {
		t.Fatal("expected non-nil exporter when webhook is configured")
	}
	defer exp.Close()

	want := sampleEvent()
	exp.Export(want)

	select {
	case ev := <-got:
		if ev.Domain != want.Domain || ev.Action != want.Action {
			t.Errorf("received event mismatch: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exporter did not deliver event to webhook")
	}
}

func TestSyslogSink_UDP_WritesRFC5424(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	sink, err := newSyslogSink("udp://" + pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("newSyslogSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Send(sampleEvent()); err != nil {
		t.Fatalf("syslog Send: %v", err)
	}

	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read udp datagram: %v", err)
	}
	line := string(buf[:n])

	for _, want := range []string{"<133>1 ", "[hydradns@32473 ", `domain="evil.com"`, `action="block"`} {
		if !strings.Contains(line, want) {
			t.Errorf("syslog datagram missing %q\nline: %s", want, line)
		}
	}
}
