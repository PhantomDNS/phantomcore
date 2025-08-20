package dnsengine

import (
	"fmt"

	"github.com/lopster568/phantomDNS/internal/config"

	"github.com/miekg/dns"
)

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		fmt.Println("Received empty DNS request")
		return
	}

	domain := r.Question[0].Name
	fmt.Println("Received request for domain:", domain)

	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return
	}

	client := new(dns.Client)
	resp, _, err := client.Exchange(r, cfg.DataPlane.UpstreamResolvers[0])
	if err != nil {
		fmt.Println("Failed to query upstream resolver:", err)

		// Avoid silent dropping of query which makes it hard to debug for the client
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			fmt.Println("Failed to write response for dropped query:", err)
		}
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		fmt.Println("Failed to write response:", err)
		return
	}

	fmt.Println("Upstream resolvers:", cfg.DataPlane.UpstreamResolvers)
}
