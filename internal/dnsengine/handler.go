package dnsengine

// func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
// 	if r == nil || len(r.Question) == 0 {
// 		logger.Log.Warn("Received empty DNS request")
// 		return
// 	}

// 	domain := r.Question[0].Name
// 	logger.Log.Infof("Received request for domain: %s", domain)

// 	// Use the upstream pool instead of dns.Client
// 	resp, err := upstreamManager.Exchange(r, 2*time.Second, 3) // 3 retries per resolver

// 	if err != nil {
// 		logger.Log.Errorf("Upstream resolution failed for %s: %v", domain, err)
// 		m := new(dns.Msg)
// 		m.SetRcode(r, dns.RcodeServerFailure)
// 		if err := w.WriteMsg(m); err != nil {
// 			logger.Log.Errorf("Failed to write failure response: %v", err)
// 		}
// 		return
// 	}
// 	if err := w.WriteMsg(resp); err != nil {
// 		logger.Log.Errorf("Failed to write response: %v", err)
// 		return
// 	}

// 	logger.Log.Infof("Query handled successfully for domain: %s", domain)
// }

// func (e *Engine) HandleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
// 	if r == nil || len(r.Question) == 0 {
// 		logger.Log.Warn("Received empty DNS request")
// 		return
// 	}

// 	domain := r.Question[0].Name
// 	logger.Log.Infof("Received request for domain: %s", domain)

// 	// Use the upstream pool instead of dns.Client
// 	resp, err := e.upstreamManager.Exchange(r, 2*time.Second, 3) // 3 retries per resolver

// 	if err != nil {
// 		logger.Log.Errorf("Upstream resolution failed for %s: %v", domain, err)
// 		m := new(dns.Msg)
// 		m.SetRcode(r, dns.RcodeServerFailure)
// 		if err := w.WriteMsg(m); err != nil {
// 			logger.Log.Errorf("Failed to write failure response: %v", err)
// 		}
// 		return
// 	}
// 	if err := w.WriteMsg(resp); err != nil {
// 		logger.Log.Errorf("Failed to write response: %v", err)
// 		return
// 	}

// 	logger.Log.Infof("Query handled successfully for domain: %s", domain)
// }
