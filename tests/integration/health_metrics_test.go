//go:build integration

package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestControlPlaneHealth checks GET /health on the control plane's published
// HTTP port. This is also a regression check for the compose.yaml port
// mismatch this PR fixes (host 8086 was published to the wrong container
// port, 8086, when the binary listens on 8080).
func TestControlPlaneHealth(t *testing.T) {
	resp, err := httpClient.Get(controlplaneURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /health response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/health status = %d, want 200: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf(`/health body = %q, want it to contain "status":"ok"`, body)
	}
}

// TestDataplaneMetrics checks GET /metrics on the dataplane's Prometheus
// endpoint (compose.yaml publishes MetricsAddr, 9153, to the host). It
// asserts on the hydradns_dns_queries_window series, which
// internal/metrics/promexport always emits on every scrape regardless of
// query volume.
func TestDataplaneMetrics(t *testing.T) {
	resp, err := httpClient.Get(metricsURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "hydradns_dns_queries_window") {
		t.Fatalf("/metrics response did not contain the expected hydradns_dns_queries_window series; first 500 bytes: %.500s", body)
	}
}
