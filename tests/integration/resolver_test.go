//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

// resolverAPI mirrors cmd/controlplane/handlers.Resolver.
type resolverAPI struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Position int    `json:"position"`
}

// createResolverRequest mirrors cmd/controlplane/handlers.CreateResolverRequest.
type createResolverRequest struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
}

// TestResolverLiveApply is the regression test for the exact bug this PR
// fixes: POST /api/v1/dns/resolvers must both persist the change AND apply
// it to the running dataplane over gRPC. It proves "applied", not just
// "the API call returned 2xx", by pointing the resolver set at a fixture
// resolver (fake-resolver, a CoreDNS instance that answers every A query
// with a fixed, obviously-fake address — see
// tests/integration/docker-compose.integration.yaml and fixtures/Corefile)
// and checking that a live DNS query through the dataplane actually returns
// that fixed address. Before the fix, CreateResolver returned HTTP 502
// ("resolver persisted but failed to apply to dataplane") in the compose
// topology, and the dataplane kept using whatever it booted with.
func TestResolverLiveApply(t *testing.T) {
	var listResp apiEnvelope[[]resolverAPI]
	status, err := authed(http.MethodGet, "/api/v1/dns/resolvers", nil, &listResp)
	if err != nil {
		t.Fatalf("list resolvers: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("list resolvers: status = %d, want 200: %+v", status, listResp)
	}
	original := listResp.Data

	// Restore the original resolver set unconditionally, regardless of
	// how the test exits, so later tests (and TestKnownGoodDomainResolves,
	// if run again) still have working internet-facing resolvers.
	t.Cleanup(func() {
		var current apiEnvelope[[]resolverAPI]
		if _, err := authed(http.MethodGet, "/api/v1/dns/resolvers", nil, &current); err == nil {
			for _, r := range current.Data {
				_, _ = authed(http.MethodDelete, "/api/v1/dns/resolvers/"+r.ID, nil, nil)
			}
		}
		for _, r := range original {
			req := createResolverRequest{Name: r.Name, Address: r.Address, Protocol: r.Protocol}
			_, _ = authed(http.MethodPost, "/api/v1/dns/resolvers", req, nil)
		}
	})

	for _, r := range original {
		if status, err := authed(http.MethodDelete, "/api/v1/dns/resolvers/"+r.ID, nil, nil); err != nil || status != http.StatusOK {
			t.Fatalf("delete existing resolver %s: status=%d err=%v", r.ID, status, err)
		}
	}

	createReq := createResolverRequest{Name: "fake-resolver", Address: "fake-resolver:53", Protocol: "udp"}
	var createResp apiEnvelope[resolverAPI]
	status, err = authed(http.MethodPost, "/api/v1/dns/resolvers", createReq, &createResp)
	if err != nil {
		t.Fatalf("create fake resolver: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("create fake resolver: status = %d, want 201 (this is the exact 502 the pre-fix dial-address bug produced): %+v",
			status, createResp)
	}

	// The apply is synchronous inside the handler (applyResolvers runs, and
	// only then does the handler respond), so a 201 above already means the
	// gRPC push to the dataplane succeeded. Still poll briefly for the DNS
	// answer to account for the dataplane rebuilding its upstream exchanger.
	domain := "resolver-live-apply-check.example"
	waitUntil(t, "resolved answer to come from the fake resolver", func() (bool, error) {
		resp, err := queryA(domain)
		if err != nil {
			return false, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return false, nil
		}
		ips := aRecords(resp)
		return len(ips) == 1 && ips[0] == fakeResolverAnswer, nil
	})
}
