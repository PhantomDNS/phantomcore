// SPDX-License-Identifier: GPL-3.0-or-later

package dnsengine

import (
	"net"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/alert"
)

// fixedClock is a deterministic alert.Clock.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// fakeDevResolver is a fake inventory keyed by client IP.
type fakeDevResolver map[string]alert.DeviceInfo

func (f fakeDevResolver) Lookup(ip string) (alert.DeviceInfo, bool) {
	d, ok := f[ip]
	return d, ok
}

// addrWriter is a mockResponseWriter with a controllable RemoteAddr so the
// engine can key alerts by a real client IP.
type addrWriter struct {
	mockResponseWriter
	remote net.Addr
}

func (w *addrWriter) RemoteAddr() net.Addr { return w.remote }

// Repeated blocklist hits from one client cross the alert threshold and produce
// an alert enriched with the device from the (fake) inventory.
func TestProcessDNSQuery_FeedsDeviceAlerter(t *testing.T) {
	bl := &mockBlocklist{blocked: map[string]bool{"c2.evil.com": true}}
	e := newTestEngine(bl, nil)

	res := fakeDevResolver{
		"192.168.1.50": {IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:50", Hostname: "roshan-laptop"},
	}
	e.alerter = alert.NewAlerter(
		alert.Config{Threshold: 3, Window: time.Hour},
		res,
		fixedClock{t: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)},
	)

	w := &addrWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 5353}}

	// First two blocked resolutions: below threshold.
	e.ProcessDNSQuery(w, newTestQuery("c2.evil.com"))
	e.ProcessDNSQuery(w, newTestQuery("c2.evil.com"))
	if got := e.Alerts(); len(got) != 0 {
		t.Fatalf("expected no alerts below threshold, got %+v", got)
	}

	// Third crosses it.
	e.ProcessDNSQuery(w, newTestQuery("c2.evil.com"))
	alerts := e.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert after crossing threshold, got %d", len(alerts))
	}
	dev := alerts[0].Device
	if dev.IP != "192.168.1.50" || dev.MAC != "aa:bb:cc:dd:ee:50" || dev.Hostname != "roshan-laptop" {
		t.Errorf("alert not enriched with device identity: %+v", dev)
	}
}

// With alerting disabled (default threshold), repeated blocked hits never
// produce an alert.
func TestProcessDNSQuery_AlerterDisabledByDefault(t *testing.T) {
	bl := &mockBlocklist{blocked: map[string]bool{"c2.evil.com": true}}
	e := newTestEngine(bl, nil)
	// Default alerter: threshold 0 (off).
	e.alerter = alert.NewAlerter(alert.Config{}, nil, nil)

	w := &addrWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 5353}}
	for i := 0; i < 20; i++ {
		e.ProcessDNSQuery(w, newTestQuery("c2.evil.com"))
	}
	if got := e.Alerts(); len(got) != 0 {
		t.Errorf("disabled alerter should produce no alerts, got %+v", got)
	}
}

func TestClientIPOnly(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.168.1.50:5353", "192.168.1.50"},
		{"[fe80::1]:53", "fe80::1"},
		{"192.168.1.50", "192.168.1.50"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := clientIPOnly(tt.in); got != tt.want {
			t.Errorf("clientIPOnly(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
