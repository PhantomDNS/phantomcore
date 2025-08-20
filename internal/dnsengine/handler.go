package dnsengine

import (
	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"

	"github.com/miekg/dns"
)

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		logger.Log.Warn("Received empty DNS request")
		return
	}

	domain := r.Question[0].Name
	logger.Log.Infof("Received request for domain: %s", domain)

	// Query the upstream resolver and log the response
	client := new(dns.Client)
	resp, _, err := client.Exchange(r, config.DefaultConfig.DataPlane.UpstreamResolvers[0])

	if err != nil {
		logger.Log.Infof("Forwarding %s to upstream %s", domain, config.DefaultConfig.DataPlane.UpstreamResolvers[0])
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			logger.Log.Errorf("Failed to write response: %v", err)
		}
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		logger.Log.Errorf("Failed to write response: %v", err)
		return
	}

	logger.Log.Infof("Query handled successfully for domain: %s", domain)
}
