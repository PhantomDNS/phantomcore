//go:build integration

package integration

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// queryA sends a single A-record query for domain to the dataplane at
// dnsAddr and returns the raw response.
func queryA(domain string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(m, dnsAddr)
	if err != nil {
		return nil, fmt.Errorf("dns exchange for %s@%s: %w", domain, dnsAddr, err)
	}
	return resp, nil
}

// aRecords extracts the A-record IP strings from a DNS response.
func aRecords(resp *dns.Msg) []string {
	var ips []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}
