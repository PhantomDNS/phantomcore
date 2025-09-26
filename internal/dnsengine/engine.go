// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"github.com/lopster568/phantomDNS/internal/utils"
	"github.com/miekg/dns"
)

type Engine struct {
	upstreamManager *UpstreamManager
	repos           *repositories.Store
	policyEngine    *policy.Engine
}

func NewDNSEngine(cfg config.DataPlaneConfig, repos *repositories.Store, pE *policy.Engine) (*Engine, error) {
	mgr, err := NewUpstreamManager(cfg.UpstreamResolvers, 4)
	if err != nil {
		return nil, err
	}
	return &Engine{
		upstreamManager: mgr,
		repos:           repos,
		policyEngine:    pE,
	}, nil
}

// Cleanup the resources used by the Engine
func (e *Engine) Shutdown() {
	if e.upstreamManager != nil {
		e.upstreamManager.Close()
	}
}

// todo: add logging of queries to the database, even if they failed
// ProcessDNSQuery processes the DNS query and returns a response
func (e *Engine) ProcessDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		logger.Log.Warn("Received empty DNS query")
		return
	}
	domainName := r.Question[0].Name
	logger.Log.Infof("Received DNS query for %s", domainName)

	decision, err := e.policyEngine.Evaluate(domainName)
	if err != nil {
		logger.Log.Error("Failed to evaluate policy: " + err.Error())
		return
	}

	if decision.Action == policy.ActionDeny {
		logger.Log.Infof("Blocking DNS query for %s", domainName)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		if err := w.WriteMsg(m); err != nil {
			logger.Log.Error("Failed to write DNS block response: " + err.Error())
		}
		// Store the blocked query in the log (CE = anonymized client IP)
		if e.repos != nil && e.repos.QueryLogs != nil {
			go func() {
				dnslog := &models.DNSQuery{
					ID:       uint(r.Id),
					Domain:   domainName,
					ClientIP: utils.AnonymizeIP(w.RemoteAddr().String()), // Consider anonymizing this if needed
					Action:   "block",
				}
				if err := e.repos.QueryLogs.Save(dnslog); err != nil {
					logger.Log.Error("Failed to log blocked DNS query: " + err.Error())
				}
			}()
		} else {
			logger.Log.Warn("Query logging is disabled: repos or QueryLogs is nil")
		}
		return
	}

	logger.Log.Infof("Allowing DNS query for %s", domainName)

	// If redirect action, create a synthetic response
	if decision.Action == policy.ActionRedirect && decision.RedirectIP != "" {
		logger.Log.Infof("Redirecting DNS query for %s to %s", domainName, decision.RedirectIP)
		m := new(dns.Msg)
		m.SetReply(r)
		rr, err := dns.NewRR(domainName + " 60 IN A " + decision.RedirectIP)
		if err != nil {
			logger.Log.Error("Failed to create redirect RR: " + err.Error())
			m.SetRcode(r, dns.RcodeServerFailure)
		}
		m.Answer = append(m.Answer, rr)
		if err := w.WriteMsg(m); err != nil {
			logger.Log.Error("Failed to write DNS redirect response: " + err.Error())
		}
		// Store the redirected query in the log (CE = anonymized client IP)
		if e.repos != nil && e.repos.QueryLogs != nil {
			go func() {
				dnslog := &models.DNSQuery{
					ID:       uint(r.Id),
					Domain:   domainName,
					ClientIP: utils.AnonymizeIP(w.RemoteAddr().String()), // Consider anonymizing this if needed
					Action:   "redirect",
				}
				if err := e.repos.QueryLogs.Save(dnslog); err != nil {
					logger.Log.Error("Failed to log redirected DNS query: " + err.Error())
				}
			}()
		} else {
			logger.Log.Warn("Query logging is disabled: repos or QueryLogs is nil")
		}
		return
	}

	// Default: ALLOW action
	const (
		defaultQueryTimeout = 5 // seconds
		maxRetries          = 2
	)
	logger.Log.Infof("Forwarding DNS query for %s to upstream", domainName)

	// Forward the query to an upstream resolver
	resp, err := e.upstreamManager.Exchange(r, defaultQueryTimeout, maxRetries)
	if err != nil {
		logger.Log.Error("Failed to get response from upstream: " + err.Error())
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// Send the response back to the client
	if err := w.WriteMsg(resp); err != nil {
		logger.Log.Error("Failed to write DNS response: " + err.Error())
	}

	// Store the query in the log (CE = anonymized client IP)
	if e.repos != nil && e.repos.QueryLogs != nil {
		go func() {
			dnslog := &models.DNSQuery{
				ID:       uint(resp.Id),
				Domain:   domainName,
				ClientIP: utils.AnonymizeIP(w.RemoteAddr().String()), // Consider anonymizing this if needed
				Action:   "allow",                                    // For now, we only allow queries
			}
			if err := e.repos.QueryLogs.Save(dnslog); err != nil {
				logger.Log.Error("Failed to log DNS query: " + err.Error())
			}
		}()
	} else {
		logger.Log.Warn("Query logging is disabled: repos or QueryLogs is nil")
	}
}
