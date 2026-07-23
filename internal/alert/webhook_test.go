// SPDX-License-Identifier: GPL-3.0-or-later

package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewWebhookSink_Empty(t *testing.T) {
	if NewWebhookSink("") != nil {
		t.Error("empty URL should yield a nil (no-op) sink")
	}
}

func TestNewWebhookSink_POSTsAlert(t *testing.T) {
	received := make(chan Alert, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		var a Alert
		if err := json.Unmarshal(body, &a); err != nil {
			t.Errorf("failed to decode alert body: %v", err)
		}
		received <- a
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewWebhookSink(srv.URL)
	if sink == nil {
		t.Fatal("expected a non-nil sink for a valid URL")
	}

	sink(Alert{
		Device:    DeviceInfo{IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:50", Hostname: "roshan-laptop"},
		Hits:      3,
		Threshold: 3,
		Domain:    "c2.evil.com",
	})

	select {
	case a := <-received:
		if a.Device.IP != "192.168.1.50" || a.Device.Hostname != "roshan-laptop" {
			t.Errorf("webhook received unexpected alert: %+v", a)
		}
		if a.Hits != 3 || a.Domain != "c2.evil.com" {
			t.Errorf("webhook payload mismatch: %+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not called within timeout")
	}
}
