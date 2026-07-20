// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/geoip"
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

// upstreamExchanger is the subset of *UpstreamManager the engine depends on.
// Declaring it as an interface keeps forwardUpstream testable without a live
// upstream. *UpstreamManager satisfies it.
type upstreamExchanger interface {
	Exchange(q *dns.Msg, timeout time.Duration, maxRetries int) (*dns.Msg, error)
	Close()
}

// NRDChecker reports whether a domain appears on the operator-configured
// newly-registered-domain (NRD) feed, and whether matches should be blocked or
// merely flagged. It is kept entirely separate from user blocklists. A nil
// checker (or one with no feed loaded) is inert.
type NRDChecker interface {
	// IsListed reports whether the domain or its registrable parent is on the feed.
	IsListed(domain string) bool
	// BlockMode reports whether listed domains are blocked (true) or flagged (false).
	BlockMode() bool
}

type RuntimeState struct {
	acceptQueries atomic.Bool
	// policyEnabled atomic.Bool
	lastError atomic.Value
}

type Engine struct {
	upstreamManager upstreamExchanger
	policyEngine    *policy.Engine
	blocklist       BlocklistChecker
	nrd             NRDChecker
	state           *RuntimeState
	metrics         *metrics.QueryMetrics
	queryLog        repositories.QueryLogRepository
	statistics      repositories.StatisticsRepository
	threatDetector  *threat.Detector
	exporter        *Exporter
	// geo is nil when ASN/GeoIP answer filtering is disabled (the default, no
	// database configured). When set, resolved answer IPs on the allow path are
	// evaluated against it.
	geo *geoip.Filter

	// fastFlux is nil when fast-flux detection is disabled (the default). When
	// set, upstream answers on the allow path are fed to it and tripping domains
	// are flagged (never blocked).
	fastFlux *fastFluxTracker

	// serveStale enables answering from an expired cache entry on upstream failure.
	serveStale bool
	// cache holds recent allowed answers for serve-stale; nil when disabled.
	cache *answerCache

	// Newly-observed-domain (NOD) detection. nodLedger is nil when NOD is
	// disabled (window <= 0). When set, nodBlock decides whether a newly
	// observed domain is blocked (true) or merely flagged and forwarded (false).
	nodLedger *nodLedger
	nodBlock  bool

	// threatBlockThreshold, when > 0, turns the heuristic threat detector from
	// log-only into enforcement: a suspicious query with ThreatScore >= threshold
	// is blocked. threatBlockDryRun logs a would-be block instead of blocking.
	threatBlockThreshold float64
	threatBlockDryRun    bool

	// abusedTLDs is the set of high-abuse TLDs to block on the default allow
	// path (lowercased, no leading dot). Empty/nil disables the feature.
	abusedTLDs map[string]bool

	// rebindProtection, when true, strips A/AAAA answers that resolve a public
	// name to a private/loopback/link-local IP. Default false (unchanged behaviour).
	rebindProtection bool

	rateLimiter *rateLimiter

	safeSearch bool
}

// safeSearchTargets maps well-known search/video hostnames to their
// enforced-safe CNAME target. When SafeSearch is enabled, a query for any
// mapped host on the allow path is answered with a CNAME to its target so the
// client re-resolves the safe endpoint. These are the vendor-documented
// SafeSearch / YouTube Restricted Mode hostnames.
var safeSearchTargets = map[string]string{
	// Google SafeSearch
	"google.com":     "forcesafesearch.google.com",
	"www.google.com": "forcesafesearch.google.com",
	// Bing strict SafeSearch
	"bing.com":     "strict.bing.com",
	"www.bing.com": "strict.bing.com",
	// DuckDuckGo safe search
	"duckduckgo.com": "safe.duckduckgo.com",
	// YouTube Restricted Mode (moderate)
	"youtube.com":             "restrictmoderate.youtube.com",
	"www.youtube.com":         "restrictmoderate.youtube.com",
	"m.youtube.com":           "restrictmoderate.youtube.com",
	"youtubei.googleapis.com": "restrictmoderate.youtube.com",
	"youtube.googleapis.com":  "restrictmoderate.youtube.com",
}

func (e *Engine) AttachBlocklistChecker(b BlocklistChecker) {
	e.blocklist = b
}

// AttachGeoFilter enables optional ASN/GeoIP answer filtering. A nil filter
// (the default) leaves the engine's allow path unchanged and adds no overhead.
func (e *Engine) AttachGeoFilter(f *geoip.Filter) {
	e.geo = f
}

// AttachNRDChecker wires the newly-registered-domain feed checker onto the
// engine. Passing a checker with no feed configured leaves NRD inert.
func (e *Engine) AttachNRDChecker(n NRDChecker) {
	e.nrd = n
}

func NewDNSEngine(cfg config.DataPlaneConfig, repos *repositories.Store, pE *policy.Engine) (*Engine, error) {
	mgr, err := NewUpstreamManager(cfg.UpstreamResolvers, 4, WithDNS0x20(cfg.DNS0x20))
	state := &RuntimeState{}
	state.acceptQueries.Store(false)
	qm := metrics.NewQueryMetrics()

	if err != nil {
		return nil, err
	}

	// Build the abused-TLD set once so the hot path does a plain map lookup
	// instead of scanning a slice or reading globals.
	var abusedTLDs map[string]bool
	if len(cfg.AbusedTLDs) > 0 {
		abusedTLDs = make(map[string]bool, len(cfg.AbusedTLDs))
		for _, t := range cfg.AbusedTLDs {
			t = strings.ToLower(strings.TrimSpace(t))
			if t != "" {
				abusedTLDs[t] = true
			}
		}
	}

	// Newly-observed-domain ledger: only enabled when a positive window is set.
	var ledger *nodLedger
	if cfg.NODWindowHours > 0 {
		ledger = newNODLedger(time.Duration(cfg.NODWindowHours)*time.Hour, nodDefaultMaxEntries, nil)
		logger.Log.Infof("NOD detection enabled: window=%dh block=%v", cfg.NODWindowHours, cfg.NODBlock)
	}

	// Event export is optional and defaults to OFF. A nil exporter is a valid
	// no-op; a bad target is logged and skipped inside NewExporter.
	exporter, err := NewExporter(cfg.SyslogAddr, cfg.EventWebhookURL)
	if err != nil {
		logger.Log.Warnf("event export disabled: %v", err)
		exporter = nil
	}

	// Typosquat/homoglyph detector: an empty brand watchlist is a no-op inside
	// Analyze, so this is always safe to construct.
	detector := threat.NewDetectorWithBrands(cfg.TyposquatBrands)
	detector.SetTyposquatBlock(cfg.TyposquatBlock)

	e := &Engine{
		upstreamManager:      mgr,
		policyEngine:         pE,
		state:                state,
		metrics:              qm,
		queryLog:             repos.QueryLogs,
		statistics:           repos.Statistics,
		threatDetector:       detector,
		exporter:             exporter,
		threatBlockThreshold: cfg.ThreatBlockThreshold,
		threatBlockDryRun:    cfg.ThreatBlockDryRun,
		abusedTLDs:           abusedTLDs,
		rebindProtection:     cfg.RebindProtection,
		rateLimiter:          newRateLimiter(cfg.ClientRateLimitPerSec),
		safeSearch:           cfg.SafeSearch,
		nodLedger:            ledger,
		nodBlock:             cfg.NODBlock,
	}
	if cfg.ServeStale {
		e.serveStale = true
		e.cache = newAnswerCache(defaultCacheSize, defaultStaleFor)
		logger.Log.Info("serve-stale enabled: expired cache answers may be served on upstream failure")
	}
	if cfg.FastFluxDetection {
		e.fastFlux = newFastFluxTracker(
			cfg.FastFluxIPThreshold,
			cfg.FastFluxTTLMaxSec,
			defaultFastFluxWindow,
			defaultFastFluxMaxDomains,
			nil,
		)
	}
	return e, nil
}

// isAbusedTLD reports whether the domain's final label (TLD) is in the
// configured high-abuse set. Returns false when the set is empty (feature off).
// domain is expected to be already normalized (lowercased, no trailing dot).
func (e *Engine) isAbusedTLD(domain string) bool {
	if len(e.abusedTLDs) == 0 {
		return false
	}
	tld := domain
	if i := strings.LastIndex(domain, "."); i >= 0 {
		tld = domain[i+1:]
	}
	return e.abusedTLDs[strings.ToLower(tld)]
}

func (e *Engine) SetAcceptQueries(enabled bool) {
	e.state.acceptQueries.Store(enabled)
}

// Cleanup the resources used by the Engine
func (e *Engine) Shutdown() {
	if e.upstreamManager != nil {
		e.upstreamManager.Close()
	}
	e.exporter.Close() // nil-safe
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

// filterRebind removes A/AAAA answer records whose IP is private, loopback,
// link-local, or unspecified. This defends against DNS rebinding, where a
// public name is resolved to an internal address to reach services behind the
// resolver. Non-A/AAAA records are always kept. It is a pure function: it
// returns the surviving records and the number that were dropped.
func filterRebind(answers []dns.RR) (kept []dns.RR, dropped int) {
	for _, rr := range answers {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			kept = append(kept, rr)
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			dropped++
			continue
		}
		kept = append(kept, rr)
	}
	return kept, dropped
}

// respondSafeSearch answers the query with a CNAME pointing the queried name
// at its enforced-safe target (e.g. www.google.com -> forcesafesearch.google.com).
// The client then re-resolves the target through normal resolution.
func (e *Engine) respondSafeSearch(w dns.ResponseWriter, r *dns.Msg, target string) {
	m := new(dns.Msg)
	m.SetReply(r)
	name := r.Question[0].Name
	rr, err := dns.NewRR(name + " 60 IN CNAME " + dns.Fqdn(target))
	if err != nil {
		logger.Log.Error("Failed to create SafeSearch CNAME RR: " + err.Error())
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		logger.Log.Error("Failed to write SafeSearch response: " + err.Error())
	}
}

// forwardOutcome reports what happened while forwarding a query upstream, for
// the caller to fold into its logging/action decision. Fast-flux is always
// advisory (flag-only); GeoIP is flag-only unless GEOIP_BLOCK is configured.
type forwardOutcome struct {
	fastFlux   bool
	geoMatched bool
	geoBlocked bool
	geoReason  string
}

// forwardUpstream forwards the query to upstream and writes the response back
// (subject to rebind-protection filtering and, when configured, the GeoIP
// filter's block decision). The returned forwardOutcome tells the caller
// whether fast-flux and/or GeoIP detectors fired.
func (e *Engine) forwardUpstream(w dns.ResponseWriter, r *dns.Msg, domain string) forwardOutcome {
	resp, err := e.upstreamManager.Exchange(r, 5, 2)
	if err != nil || resp == nil {
		if err != nil {
			logger.Log.Error("Upstream query failed: " + err.Error())
		} else {
			logger.Log.Error("Upstream returned nil response for: " + domain)
		}
		// Serve-stale: when enabled, answer from an expired cache entry (if one
		// exists) instead of SERVFAIL so a transient upstream blip does not take
		// DNS down. Disabled by default, so the default behavior is unchanged.
		if e.serveStale && e.cache != nil {
			if ent, ok := e.cache.GetStale(cacheKey(r.Question[0])); ok {
				logger.Log.Warnf("Serving stale answer for %s (upstream unavailable)", domain)
				if werr := w.WriteMsg(ent.reply(r, staleTTL)); werr != nil {
					logger.Log.Error("Failed to write stale DNS response: " + werr.Error())
				}
				return forwardOutcome{}
			}
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return forwardOutcome{}
	}
	// Cache successful answers so they can back a future serve-stale response.
	if e.serveStale && e.cache != nil && resp.Rcode == dns.RcodeSuccess {
		e.cache.Put(cacheKey(r.Question[0]), resp)
	}

	// Fast-flux detection (flag-only, never blocks). Inspect the answer's A/AAAA
	// records before writing the response back.
	outcome := forwardOutcome{}
	if e.fastFlux != nil {
		if ips, ttl, ok := extractAnswerIPs(resp); ok && e.fastFlux.observe(domain, ips, ttl) {
			outcome.fastFlux = true
			logger.Log.Warnf("Fast-flux suspected: %s (distinct-IP churn with low TTL within window)", domain)
		}
	}

	// DNS rebinding protection: strip answers that map a public name to an
	// internal IP. If dropping them leaves an A/AAAA query with no answers at
	// all, block the response outright instead of returning an empty reply.
	if e.rebindProtection {
		kept, dropped := filterRebind(resp.Answer)
		if dropped > 0 {
			logger.Log.Warnf("Rebind protection dropped %d record(s) for %s", dropped, domain)
			resp.Answer = kept
			qtype := r.Question[0].Qtype
			if len(kept) == 0 && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
				e.respondBlocked(w, r, domain, "rebind")
				return outcome
			}
		}
	}

	// Optional ASN/GeoIP answer filtering. Disabled (e.geo nil) unless a
	// database is configured, keeping the original zero-overhead fast path.
	if e.geo != nil {
		if d := e.geo.Evaluate(answerIPs(resp)); d.Matched {
			outcome.geoMatched = true
			outcome.geoReason = d.Reason
			if d.Block {
				outcome.geoBlocked = true
				logger.Log.Infof("Blocking via GeoIP filter: %s (%s)", domain, d.Reason)
				e.respondBlocked(w, r, domain, "geoip")
				return outcome
			}
			logger.Log.Warnf("GeoIP flagged answer for %s: %s", domain, d.Reason)
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		logger.Log.Error("Failed to write DNS response: " + err.Error())
	}
	return outcome
}

// normalizeDomain lowercases and strips the trailing dot from a DNS FQDN.
func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(d), ".")
}

// clientIPFromAddr extracts the host portion (IP) from a net.Addr so the rate
// limiter keys on the client IP rather than the ephemeral source port, which
// changes on every UDP query.
func clientIPFromAddr(addr net.Addr) string {
	s := addr.String()
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
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

	// --- Per-client rate limiting (default OFF; allows all when disabled) ---
	rlClientIP := ""
	if addr := w.RemoteAddr(); addr != nil {
		rlClientIP = clientIPFromAddr(addr)
	}
	if !e.rateLimiter.allow(rlClientIP) {
		logger.Log.Warnf("Rate limit exceeded for client %s, refusing query", rlClientIP)
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
			e.logQuery(domainName, clientIP, "block", "blocklist", threatResult)
			e.metrics.RecordBlocked()
			e.respondBlocked(w, r, domainName, "blocklist")
			success = true
			return
		}
	}

	// --- Step 1.5: Newly-registered-domain (NRD) feed ---
	// The NRD set is kept entirely separate from user blocklists. In block mode a
	// match is treated like a blocklist hit and short-circuits here; in flag mode
	// the query continues and is flagged on the allow path below. Inert when no
	// feed is configured.
	nrdListed := false
	if e.nrd != nil {
		nrdListed = e.nrd.IsListed(domainName)
		if nrdListed && e.nrd.BlockMode() {
			logger.Log.Infof("Blocked by NRD feed: %s", domainName)
			e.logQuery(domainName, clientIP, "block", "nrd", threatResult)
			e.respondBlocked(w, r, domainName, "nrd")
			success = true
			return
		}
	}

	// --- Step 2: Evaluate policy ---
	decision, err := e.policyEngine.Evaluate(domainName)
	if err != nil {
		logger.Log.Error("Failed to evaluate policy: " + err.Error())
		e.logQuery(domainName, clientIP, "error", "", threatResult)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	switch decision.Action {
	case policy.ActionDeny:
		logger.Log.Infof("Blocking via policy %s", decision.PolicyID)
		e.logQuery(domainName, clientIP, "block", decision.PolicyID, threatResult)
		e.metrics.RecordBlocked()
		e.respondBlocked(w, r, domainName, decision.PolicyID)
		success = true

	case policy.ActionRedirect:
		e.logQuery(domainName, clientIP, "redirect", "redirect:"+decision.PolicyID, threatResult)
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
			e.logQuery(domainName, clientIP, "block", "threat:"+threatResult.DetectionMethod, threatResult)
			e.respondBlocked(w, r, domainName, "threat:"+threatResult.DetectionMethod)
			success = true
			return
		case threatDryRun:
			logger.Log.Warnf("[threat dry-run] would block %s (score=%.2f >= %.2f, method=%s)",
				domainName, threatResult.ThreatScore, e.threatBlockThreshold, threatResult.DetectionMethod)
		}

		// Abused-TLD block applies only on the default allow path (no explicit
		// policy matched). An explicit ALLOW policy, which carries a PolicyID,
		// still wins and is forwarded normally.
		if decision.PolicyID == "" && e.isAbusedTLD(domainName) {
			logger.Log.Infof("Blocking via abused TLD: %s", domainName)
			e.logQuery(domainName, clientIP, "block", "abused-tld", threatResult)
			e.respondBlocked(w, r, domainName, "abused-tld")
			success = true
			return
		}

		// SafeSearch enforcement: on the allow path, rewrite well-known search/
		// video hosts to their enforced-safe target via a CNAME so the client
		// re-resolves the safe endpoint. Never overrides a block/redirect above.
		if e.safeSearch {
			if target, ok := safeSearchTargets[domainName]; ok {
				logger.Log.Infof("SafeSearch rewrite: %s -> %s", domainName, target)
				e.logQuery(domainName, clientIP, "allow", "", threatResult)
				e.respondSafeSearch(w, r, target)
				success = true
				return
			}
		}

		// Newly-observed-domain (NOD) detection runs only on the allow path, so
		// it never overrides an explicit block/redirect decided above. observe()
		// records the domain on first sight and reports whether it is new.
		nodNew := e.nodLedger != nil && e.nodLedger.observe(domainName)
		if nodNew && e.nodBlock {
			logger.Log.Infof("Blocking newly-observed domain: %s", domainName)
			e.logQuery(domainName, clientIP, "block", "nod", threatResult)
			e.respondBlocked(w, r, domainName, "nod")
			success = true
			return
		}
		if nodNew {
			// Flag-only mode: annotate as suspicious and forward normally.
			threatResult.IsSuspicious = true
			if threatResult.DetectionMethod == "" {
				threatResult.DetectionMethod = "nod"
			}
			if threatResult.Reason == "" {
				threatResult.Reason = "newly observed domain (first seen within NOD window)"
			}
		}

		action := "allow"
		reason := ""
		if threatResult.IsSuspicious {
			// Opt-in blocking (e.g. typosquat block mode): drop instead of forward.
			if threatResult.Block {
				logger.Log.Warnf("Suspicious domain blocked: %s (score=%.2f, method=%s)", domainName, threatResult.ThreatScore, threatResult.DetectionMethod)
				e.logQuery(domainName, clientIP, "block", threatResult.DetectionMethod, threatResult)
				e.respondBlocked(w, r, domainName, threatResult.DetectionMethod)
				success = true
				return
			}
			action = "flagged"
			reason = threatResult.DetectionMethod
			logger.Log.Warnf("Suspicious domain allowed: %s (score=%.2f, method=%s)", domainName, threatResult.ThreatScore, threatResult.DetectionMethod)
		} else if nrdListed {
			// Flag mode: forward the query but mark it as newly-registered.
			threatResult.IsSuspicious = true
			threatResult.DetectionMethod = "nrd"
			threatResult.Reason = "newly-registered domain (on NRD feed)"
			action = "flagged"
			reason = threatResult.DetectionMethod
			logger.Log.Warnf("Newly-registered domain allowed (flagged): %s", domainName)
		}
		// Forward first so the fast-flux heuristic and the optional GeoIP filter
		// can inspect the answer, then log — a tripped domain is flagged/blocked
		// based on which detector fired.
		outcome := e.forwardUpstream(w, r, domainName)
		if outcome.fastFlux {
			action = "flagged"
			if !threatResult.IsSuspicious {
				threatResult.IsSuspicious = true
				threatResult.DetectionMethod = "fast-flux"
				threatResult.Reason = "fast-flux: distinct-IP churn with low TTL"
			}
			reason = threatResult.DetectionMethod
		}
		if outcome.geoMatched {
			threatResult = enrichThreat(threatResult, outcome.geoReason)
			reason = threatResult.DetectionMethod
			if outcome.geoBlocked {
				action = "block"
			} else {
				action = "flagged"
			}
		}
		e.logQuery(domainName, clientIP, action, reason, threatResult)
		success = true
	}
}

// answerIPs extracts the A and AAAA record IPs from a DNS response.
func answerIPs(resp *dns.Msg) []net.IP {
	if resp == nil {
		return nil
	}
	ips := make([]net.IP, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}
	return ips
}

// enrichThreat folds a GeoIP match into a threat result so it is logged as
// suspicious without clobbering an existing heuristic detection.
func enrichThreat(tr threat.Result, reason string) threat.Result {
	tr.IsSuspicious = true
	if tr.DetectionMethod == "" {
		tr.DetectionMethod = "geoip"
	}
	if tr.Reason == "" {
		tr.Reason = reason
	}
	if tr.ThreatScore == 0 {
		tr.ThreatScore = 0.6
	}
	return tr
}

func (e *Engine) logQuery(domain, clientIP, action, reason string, tr threat.Result) {
	// Export the event to external sinks (syslog/webhook) if enabled.
	// Non-blocking with drop-on-full; a nil exporter is a no-op.
	e.exporter.Export(Event{
		Timestamp:       time.Now().UTC(),
		Domain:          domain,
		ClientIP:        clientIP,
		Action:          action,
		IsSuspicious:    tr.IsSuspicious,
		ThreatScore:     tr.ThreatScore,
		DetectionMethod: tr.DetectionMethod,
		ThreatReason:    tr.Reason,
	})

	if e.queryLog == nil {
		return
	}
	q := &models.DNSQuery{
		Domain:          domain,
		ClientIP:        clientIP,
		Action:          action,
		BlockReason:     reason,
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
