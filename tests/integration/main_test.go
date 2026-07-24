//go:build integration

// Package integration exercises hydra-core end to end against a real running
// compose stack (dataplane + controlplane, real gRPC bridge, real SQLite
// storage) over the network, the same way an operator or the UI would. It
// intentionally does not import the module's own internal/cmd packages: it
// speaks the DNS wire protocol (via miekg/dns) and the control-plane's plain
// HTTP JSON API, exactly like an external client.
//
// Every test address is overridable via environment variables so the suite
// can run against any reachable stack; the defaults match compose.yaml plus
// tests/integration/docker-compose.integration.yaml, which is what the CI
// "Integration Tests" job (.github/workflows/ci.yaml) brings up.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// Fixture domains served by tests/integration/fixtures/blocklist.txt and
// created directly via the policy API. Both use the reserved .test TLD
// (RFC 2606) so a real upstream resolver always returns NXDOMAIN for them
// when hydra-core is not itself blocking or sinkholing the query — that is
// what makes "blocked vs not blocked" observable from outside the box.
const (
	blocklistFixtureDomain = "hydra-integration-blocklist.test"
	policyFixtureDomain    = "hydra-integration-policy.test"

	// fakeResolverAnswer is the fixed A record tests/integration/fixtures/Corefile
	// always returns, used to prove a live resolver-set change actually took
	// effect (the dataplane forwarded to the new resolver, not the real
	// internet or a stale cached exchanger).
	fakeResolverAnswer = "203.0.113.99"

	adminPassword = "integration-tests-password-1"

	pollInterval = 250 * time.Millisecond
	// pollTimeout comfortably covers the dataplane's 5s DB-poll cycle
	// (cmd/dataplane/main.go reloadPolicies ticker) plus scheduling slack.
	pollTimeout = 10 * time.Second
)

var (
	dnsAddr         string
	controlplaneURL string
	metricsURL      string

	httpClient = &http.Client{Timeout: 10 * time.Second}
	authToken  string
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func TestMain(m *testing.M) {
	dnsAddr = envOr("HYDRA_DNS_ADDR", "127.0.0.1:1053")
	controlplaneURL = envOr("HYDRA_CONTROLPLANE_URL", "http://127.0.0.1:8086")
	metricsURL = envOr("HYDRA_METRICS_URL", "http://127.0.0.1:9153")

	token, err := ensureAuthToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration setup: failed to obtain an auth token: %v\n", err)
		os.Exit(1)
	}
	authToken = token

	os.Exit(m.Run())
}

// ensureAuthToken completes first-boot setup against a fresh stack, or logs
// in if setup already ran (e.g. the suite was run twice against the same
// stack during local iteration).
func ensureAuthToken() (string, error) {
	setupBody := map[string]string{"password": adminPassword}
	var setupResp apiEnvelope[map[string]string]
	status, err := doJSON(http.MethodPost, "/api/v1/auth/setup", "", setupBody, &setupResp)
	if err != nil {
		return "", fmt.Errorf("POST /api/v1/auth/setup: %w", err)
	}
	switch status {
	case http.StatusOK:
		token := setupResp.Data["token"]
		if token == "" {
			return "", fmt.Errorf("setup succeeded but returned no token: %+v", setupResp)
		}
		return token, nil
	case http.StatusConflict:
		// Setup already completed against this stack; fall through to login.
	default:
		return "", fmt.Errorf("unexpected status %d from setup: %+v", status, setupResp)
	}

	loginBody := map[string]string{"password": adminPassword}
	var loginResp apiEnvelope[map[string]string]
	status, err = doJSON(http.MethodPost, "/api/v1/auth/login", "", loginBody, &loginResp)
	if err != nil {
		return "", fmt.Errorf("POST /api/v1/auth/login: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("login failed with status %d: %+v (setup password mismatch from a prior run?)", status, loginResp)
	}
	token := loginResp.Data["token"]
	if token == "" {
		return "", fmt.Errorf("login succeeded but returned no token: %+v", loginResp)
	}
	return token, nil
}

// apiEnvelope mirrors the control plane's uniform JSON response shape
// ({"status": "...", "data": ..., "error": "..."}) without importing the
// package that defines it.
type apiEnvelope[T any] struct {
	Status string  `json:"status"`
	Data   T       `json:"data"`
	Error  *string `json:"error"`
}

// doJSON issues an HTTP request against the control plane. token, when
// non-empty, is sent as a Bearer token; pass "" for the unauthenticated
// auth endpoints. body is marshaled as the JSON request body when non-nil.
// out, when non-nil, receives the JSON-decoded response body.
func doJSON(method, path, token string, body, out any) (int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, controlplaneURL+path, reqBody)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unmarshal response body %q: %w", respBody, err)
		}
	}
	return resp.StatusCode, nil
}

// authed is a doJSON shorthand that always sends the shared test session's
// Bearer token.
func authed(method, path string, body, out any) (int, error) {
	return doJSON(method, path, authToken, body, out)
}

// waitUntil polls cond every pollInterval until it returns true, or fails the
// test once pollTimeout elapses. cond should return (false, nil) to keep
// polling, (true, nil) once satisfied, or (_, err) to record a diagnostic
// while still retrying (useful for "not ready yet" errors like connection
// refused during a brief container restart).
func waitUntil(t *testing.T, what string, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	var lastErr error
	var lastOK bool
	for time.Now().Before(deadline) {
		ok, err := cond()
		lastOK, lastErr = ok, err
		if err == nil && ok {
			return
		}
		time.Sleep(pollInterval)
	}
	if lastErr != nil {
		t.Fatalf("timed out after %s waiting for %s: %v", pollTimeout, what, lastErr)
	}
	t.Fatalf("timed out after %s waiting for %s (last result: %v)", pollTimeout, what, lastOK)
}
