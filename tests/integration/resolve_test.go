//go:build integration

package integration

import (
	"testing"

	"github.com/miekg/dns"
)

// TestKnownGoodDomainResolves is the baseline sanity check: a well-known,
// unblocked domain resolves NOERROR with at least one A record through the
// dataplane's default upstream resolvers (compose.yaml ships 8.8.8.8 and
// 1.1.1.1). If this fails, nothing else in the suite is trustworthy either.
func TestKnownGoodDomainResolves(t *testing.T) {
	resp, err := queryA("example.com")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	ips := aRecords(resp)
	if len(ips) == 0 {
		t.Fatalf("expected at least one A record, got none (answer section: %+v)", resp.Answer)
	}
	t.Logf("example.com -> %v", ips)
}
