// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/metrics"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"github.com/lopster568/phantomDNS/internal/threat"
	"github.com/miekg/dns"
)

type BlocklistChecker interface {
	IsBlocked(domain string) (bool, error)
}

type RuntimeState struct {
	acceptQueries atomic.Bool
	// policyEnabled atomic.Bool
	lastError atomic.Value
}

type Engine struct {
	upstreamManager *UpstreamManager
	policyEngine    *policy.Engine
	blocklist       BlocklistChecker
	state           *RuntimeState
	metrics         *metrics.QueryMetrics
	queryLog        repositories.QueryLogRepository
	statistics      repositories.StatisticsRepository
	threatDetector  *threat.Detector

	// threatBlockThreshold, when > 0, turns the heuristic threat detector from
	// log-only into enforcement: a suspicious query with ThreatScore >= threshold
	// is blocked. threatBlockDryRun logs a would-be block instead of blocking.
	threatBlockThreshold float64
	threatBlockDryRun    bool
}

func (e *Engine) AttachBlocklistChecker(b BlocklistChecker) {
	e.blocklist = b
}

func NewDNSEngine(cfg config.DataPlaneConfig, repos *repositories.Store, pE *policy.Engine) (*Engine, error) {
	mgr, err := NewUpstreamManager(cfg.UpstreamResolvers, 4)
	state := &RuntimeState{}
	state.acceptQueries.Store(false)
	qm := metrics.NewQueryMetrics()

	if err != nil {
		return nil, err
	}
	return &Engine{
		upstreamManager:      mgr,
		policyEngine:         pE,
		state:                state,
		metrics:              qm,
		queryLog:             repos.QueryLogs,
		statistics:           repos.Statistics,
		threatDetector:       threat.NewDetector(),
		threatBlockThreshold: cfg.ThreatBlockThreshold,
		threatBlockDryRun:    cfg.ThreatBlockDryRun,
	}, nil
}

func (e *Engine) SetAcceptQueries(enabled bool) {
	e.state.acceptQueries.Store(enabled)
}

// Cleanup the resources used by the Engine
func (e *Engine) Shutdown() {
	if e.upstreamManager != nil {
		e.upstreamManager.Close()
	}
}

func (e *Engine) respondBlocked(w dns.ResponseWriter, r *dns.Msg, domain, reason string) {
	m := new(dns.Msg)
	m.SetReply(r)
	// Return 0.0.0.0 / :: instead of REFUSED — browsers treat REFUSED as "try another DNS"
	// but 0.0.0.0 causes an immediate connection failure (ERR_CONNECTION_REFUSED)
	qtype := r.Question[0].Qtype
	name := r.Question[0].Name
	switch qtype {
	case dns.TypeAAAA:
		rr, err := dns.NewRR(name + " 60 IN AAAA ::")
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
	default: // TypeA and everything else
		rr, err := dns.NewRR(name + " 60 IN A 0.0.0.0")
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
	}
	if err := w.WriteMsg(m); err != nil {
		logger.Log.Error("Failed to write DNS block response: " + err.Error())
	}
}

func (e *Engine) respondRedirect(w dns.ResponseWriter, r *dns.Msg, domain, ip string) {
	m := new(dns.Msg)
	m.SetReply(r)
	rr, err := dns.NewRR(domain + " 60 IN A " + ip)
	if err != nil {
		logger.Log.Error("Failed to create redirect RR: " + err.Error())
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		logger.Log.Error("Failed to write DNS redirect response: " + err.Error())
	}
}

func (e *Engine) forwardUpstream(w dns.ResponseWriter, r *dns.Msg, domain string) {
	resp, err := e.upstreamManager.Exchange(r, 5, 2)
	if err != nil {
		logger.Log.Error("Upstream query failed: " + err.Error())
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	if resp == nil {
		logger.Log.Error("Upstream returned nil response for: " + domain)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		logger.Log.Error("Failed to write DNS response: " + err.Error())
	}
}

// normalizeDomain lowercases and strips the trailing dot from a DNS FQDN.
func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(d), ".")
}

// Known private/local DNS suffixes appended by routers via DHCP search domains.
// When a router advertises a search domain (e.g., "hgu_lan", "home", "local"),
// Windows/macOS append it to bare hostnames AND sometimes to FQDNs.
// We strip these before blocklist/policy checks so "godaddy.com.hgu_lan"
// still matches the "godaddy.com" block rule.
var localSuffixes = map[string]bool{
	"lan": true, "local": true, "home": true, "internal": true,
	"localdomain": true, "domain.name": true, "hgu_lan": true,
	"fritz.box": true, "mynetwork": true, "belkin": true,
	"router": true, "gateway": true, "dlink": true,
}

// stripSearchDomain removes known router-appended search domains from a query.
// e.g., "godaddy.com.hgu_lan" → "godaddy.com"
func stripSearchDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		return domain
	}

	// Check last 1 and last 2 labels against known suffixes
	lastOne := parts[len(parts)-1]
	lastTwo := strings.Join(parts[len(parts)-2:], ".")

	if localSuffixes[lastTwo] {
		return strings.Join(parts[:len(parts)-2], ".")
	}
	if localSuffixes[lastOne] {
		return strings.Join(parts[:len(parts)-1], ".")
	}

	return domain
}

// threatAction is the enforcement decision for a scored query.
type threatAction int

const (
	threatNone   threatAction = iota // do not enforce; forward as usual
	threatBlock                      // block the query
	threatDryRun                     // log a would-be block, but still allow
)

// shouldEnforceThreat reports whether a scored threat result crosses the
// configured block threshold. A threshold of 0 disables enforcement, preserving
// the historical log-only behaviour.
func shouldEnforceThreat(tr threat.Result, threshold float64) bool {
	return threshold > 0 && tr.IsSuspicious && tr.ThreatScore >= threshold
}

// threatDecision maps a scored result to an enforcement action for this engine.
func (e *Engine) threatDecision(tr threat.Result) threatAction {
	if !shouldEnforceThreat(tr, e.threatBlockThreshold) {
		return threatNone
	}
	if e.threatBlockDryRun {
		return threatDryRun
	}
	return threatBlock
}

// ProcessDNSQuery processes the DNS query and returns a response
func (e *Engine) ProcessDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		return
	}

	if !e.state.acceptQueries.Load() {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	start := time.Now()
	success := false

	defer func() {
		elapsed := time.Since(start)
		e.metrics.Record(elapsed, success)
	}()

	domainName := stripSearchDomain(normalizeDomain(r.Question[0].Name))
	clientIP := ""
	if w.RemoteAddr() != nil {
		clientIP = w.RemoteAddr().String()
	}

	// Run threat detection on every query (non-blocking, just scoring)
	var threatResult threat.Result
	if e.threatDetector != nil {
		threatResult = e.threatDetector.Analyze(domainName)
	}

	// --- Step 1: Check blocklist first ---
	if e.blocklist != nil {
		blocked, err := e.blocklist.IsBlocked(domainName)
		if err != nil {
			logger.Log.Error("Blocklist check failed: " + err.Error())
		} else if blocked {
			logger.Log.Infof("Blocked by blocklist: %s", domainName)
			e.logQuery(domainName, clientIP, "block", threatResult)
			e.respondBlocked(w, r, domainName, "blocklist")
			success = true
			return
		}
	}

	// --- Step 2: Evaluate policy ---
	decision, err := e.policyEngine.Evaluate(domainName)
	if err != nil {
		logger.Log.Error("Failed to evaluate policy: " + err.Error())
		e.logQuery(domainName, clientIP, "error", threatResult)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	switch decision.Action {
	case policy.ActionDeny:
		logger.Log.Infof("Blocking via policy %s", decision.PolicyID)
		e.logQuery(domainName, clientIP, "block", threatResult)
		e.respondBlocked(w, r, domainName, decision.PolicyID)
		success = true

	case policy.ActionRedirect:
		e.logQuery(domainName, clientIP, "redirect", threatResult)
		e.respondRedirect(w, r, domainName, decision.RedirectIP)
		success = true

	default: // policy.ActionAllow
		// The query is not on any blocklist or block policy. If threat enforcement
		// is enabled, a sufficiently suspicious domain is blocked here (dry-run only
		// logs). Threshold 0 keeps the historical log-only behaviour.
		switch e.threatDecision(threatResult) {
		case threatBlock:
			logger.Log.Warnf("Blocking suspicious domain %s (score=%.2f >= %.2f, method=%s)",
				domainName, threatResult.ThreatScore, e.threatBlockThreshold, threatResult.DetectionMethod)
			e.logQuery(domainName, clientIP, "block", threatResult)
			e.respondBlocked(w, r, domainName, "threat:"+threatResult.DetectionMethod)
			success = true
			return
		case threatDryRun:
			logger.Log.Warnf("[threat dry-run] would block %s (score=%.2f >= %.2f, method=%s)",
				domainName, threatResult.ThreatScore, e.threatBlockThreshold, threatResult.DetectionMethod)
		}

		action := "allow"
		if threatResult.IsSuspicious {
			action = "flagged"
			logger.Log.Warnf("Suspicious domain allowed: %s (score=%.2f, method=%s)", domainName, threatResult.ThreatScore, threatResult.DetectionMethod)
		}
		e.logQuery(domainName, clientIP, action, threatResult)
		e.forwardUpstream(w, r, domainName)
		success = true
	}
}

func (e *Engine) logQuery(domain, clientIP, action string, tr threat.Result) {
	if e.queryLog == nil {
		return
	}
	q := &models.DNSQuery{
		Domain:          domain,
		ClientIP:        clientIP,
		Action:          action,
		IsSuspicious:    tr.IsSuspicious,
		ThreatScore:     tr.ThreatScore,
		DetectionMethod: tr.DetectionMethod,
		ThreatReason:    tr.Reason,
	}
	// Map "flagged" to "allow" for statistics (flagged domains are still forwarded)
	statsAction := action
	if statsAction == "flagged" {
		statsAction = "allow"
	}

	go func() {
		if err := e.queryLog.Save(q); err != nil {
			logger.Log.Errorf("Failed to log query: %v", err)
		}
		if e.statistics != nil {
			if err := e.statistics.IncrementCounter(statsAction); err != nil {
				logger.Log.Errorf("Failed to increment stats: %v", err)
			}
		}
	}()
}

func (e *Engine) Metrics() *metrics.QueryMetrics {
	return e.metrics
}
