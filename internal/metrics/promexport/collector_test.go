// SPDX-License-Identifier: GPL-3.0-or-later
package promexport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/metrics"
)

func TestMetricsEndpoint(t *testing.T) {
	qm := metrics.NewQueryMetrics()
	qm.Record(1*time.Millisecond, true)
	qm.Record(30*time.Millisecond, true)
	qm.Record(600*time.Millisecond, false)

	// Mirror the production wiring: mount the handler at /metrics.
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler(qm))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort cleanup, test outcome doesn't depend on it

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	wantNames := []string{
		"hydradns_dns_queries_window",
		"hydradns_dns_query_errors_window",
		"hydradns_dns_query_latency_seconds",
	}
	for _, name := range wantNames {
		if !strings.Contains(out, name) {
			t.Errorf("expected metric %q in exposition, not found", name)
		}
	}

	// Values must reflect the recorded queries, not a parallel counter.
	if !strings.Contains(out, "hydradns_dns_queries_window 3") {
		t.Errorf("expected queries_window == 3, exposition:\n%s", out)
	}
	if !strings.Contains(out, "hydradns_dns_query_errors_window 1") {
		t.Errorf("expected query_errors_window == 1, exposition:\n%s", out)
	}

	// Percentile quantile labels must be present.
	for _, q := range []string{`quantile="0.5"`, `quantile="0.95"`, `quantile="0.99"`} {
		if !strings.Contains(out, q) {
			t.Errorf("expected latency series with %s, not found", q)
		}
	}
}
