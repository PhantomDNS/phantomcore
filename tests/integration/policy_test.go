//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

// createPolicyRequest mirrors cmd/controlplane/handlers.CreatePolicyRequest
// (only the fields this test needs).
type createPolicyRequest struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Action   string   `json:"action"`
	Domains  []string `json:"domains"`
	Priority int      `json:"priority"`
}

// TestPolicyCRUDRoundtrip creates a "block" policy for a domain that would
// otherwise be NXDOMAIN (reserved .test TLD), confirms the dataplane starts
// blocking it, deletes the policy, and confirms the dataplane reverts to
// NXDOMAIN. The dataplane reloads its policy snapshot from storage on a 5s
// ticker (cmd/dataplane/main.go), not per query, so both directions poll
// within that window instead of asserting immediately.
func TestPolicyCRUDRoundtrip(t *testing.T) {
	const policyID = "integration-test-policy"

	// Best-effort cleanup in case an assertion fails partway through and the
	// test doesn't reach the explicit delete below.
	t.Cleanup(func() {
		_, _ = authed(http.MethodDelete, "/api/v1/policies/"+policyID, nil, nil)
	})

	// Baseline: confirm the fixture domain is NOT already blocked before we
	// create the policy, so "becomes blocked" is a real transition.
	waitUntil(t, "policy fixture domain to start as NXDOMAIN", func() (bool, error) {
		resp, err := queryA(policyFixtureDomain)
		if err != nil {
			return false, err
		}
		return resp.Rcode == dns.RcodeNameError, nil
	})

	createReq := createPolicyRequest{
		ID:       policyID,
		Name:     policyID,
		Action:   "block",
		Domains:  []string{policyFixtureDomain},
		Priority: 100,
	}
	var createResp apiEnvelope[map[string]any]
	status, err := authed(http.MethodPost, "/api/v1/policies", createReq, &createResp)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("create policy: status = %d, want 200/201: %+v", status, createResp)
	}

	waitUntil(t, "policy fixture domain to become blocked", func() (bool, error) {
		resp, err := queryA(policyFixtureDomain)
		if err != nil {
			return false, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return false, nil
		}
		ips := aRecords(resp)
		return len(ips) == 1 && ips[0] == "0.0.0.0", nil
	})

	status, err = authed(http.MethodDelete, "/api/v1/policies/"+policyID, nil, nil)
	if err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("delete policy: status = %d, want 200/204", status)
	}

	waitUntil(t, "policy fixture domain to revert to NXDOMAIN", func() (bool, error) {
		resp, err := queryA(policyFixtureDomain)
		if err != nil {
			return false, err
		}
		return resp.Rcode == dns.RcodeNameError, nil
	})
}
