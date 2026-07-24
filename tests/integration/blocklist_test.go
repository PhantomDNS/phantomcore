//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

// createBlocklistRequest mirrors cmd/controlplane/handlers.CreateBlocklistRequest.
type createBlocklistRequest struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Format string `json:"format"`
}

// TestBlocklistSourceSinkholes adds a real blocklist source (served by the
// blocklist-fixture container, see tests/integration/docker-compose.integration.yaml)
// through the control-plane API and confirms the fixture domain, which is
// otherwise NXDOMAIN (reserved .test TLD, not a real registration), starts
// resolving as a sinkholed 0.0.0.0 answer. Blocklist checks are read live
// per query (BlocklistChecker.IsBlocked), no cache/refresh delay, but the
// fetch/parse/store of the source itself is still an out-of-band step, so
// this polls briefly rather than asserting on the very first query.
func TestBlocklistSourceSinkholes(t *testing.T) {
	const sourceID = "integration-test-blocklist"

	t.Cleanup(func() {
		_, _ = authed(http.MethodDelete, "/api/v1/blocklists/"+sourceID, nil, nil)
	})

	createReq := createBlocklistRequest{
		ID:     sourceID,
		Name:   sourceID,
		URL:    "http://blocklist-fixture/blocklist.txt",
		Format: "domains",
	}
	var createResp apiEnvelope[map[string]any]
	status, err := authed(http.MethodPost, "/api/v1/blocklists", createReq, &createResp)
	if err != nil {
		t.Fatalf("create blocklist source: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("create blocklist source: status = %d, want 201: %+v", status, createResp)
	}

	waitUntil(t, "blocklist fixture domain to sinkhole", func() (bool, error) {
		resp, err := queryA(blocklistFixtureDomain)
		if err != nil {
			return false, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return false, nil
		}
		ips := aRecords(resp)
		return len(ips) == 1 && ips[0] == "0.0.0.0", nil
	})
}
