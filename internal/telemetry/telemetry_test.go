// SPDX-License-Identifier: GPL-3.0-or-later
package telemetry

import (
	"context"
	"testing"

	"github.com/lopster568/phantomDNS/internal/config"
)

// TestReport_NoOpUnderLocalOnly verifies the gated helper makes NO outbound
// attempt when custody mode is engaged.
func TestReport_NoOpUnderLocalOnly(t *testing.T) {
	t.Setenv("LOCAL_ONLY", "true")

	sent := false
	r := NewReporter(func(ctx context.Context, event string) error {
		sent = true
		return nil
	})

	if err := r.Report(context.Background(), "startup"); err != nil {
		t.Fatalf("Report() returned error under LOCAL_ONLY: %v", err)
	}
	if sent {
		t.Fatalf("outbound sender was invoked under LOCAL_ONLY; custody contract violated")
	}
}

// TestReport_SendsWhenCustodyOff verifies normal operation (default false)
// still performs the outbound call.
func TestReport_SendsWhenCustodyOff(t *testing.T) {
	t.Setenv("LOCAL_ONLY", "false")
	config.DefaultConfig.LocalOnly = false

	sent := false
	var gotEvent string
	r := NewReporter(func(ctx context.Context, event string) error {
		sent = true
		gotEvent = event
		return nil
	})

	if err := r.Report(context.Background(), "startup"); err != nil {
		t.Fatalf("Report() returned error: %v", err)
	}
	if !sent {
		t.Fatalf("outbound sender was not invoked when custody mode is off")
	}
	if gotEvent != "startup" {
		t.Fatalf("sender got event %q, want %q", gotEvent, "startup")
	}
}
