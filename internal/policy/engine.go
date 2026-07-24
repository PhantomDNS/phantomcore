package policy

import (
	"net"
	"strings"
	"sync/atomic"
	"time"
)

type Engine struct {
	snapshot atomic.Value // holds *Snapshot
	// now supplies the current time for schedule evaluation (I-038). It is
	// injectable so tests can make scheduled-policy behaviour deterministic.
	// Only scheduled policies consult it.
	now func() time.Time
}

func NewPolicyEngine() *Engine {
	return NewPolicyEngineWithClock(nil)
}

// NewPolicyEngineWithClock builds an engine with an injectable clock. Passing
// nil uses time.Now. Only schedule evaluation reads the clock; the fast path
// for unscheduled policies never does.
func NewPolicyEngineWithClock(clock func() time.Time) *Engine {
	if clock == nil {
		clock = time.Now
	}
	e := &Engine{now: clock}
	e.snapshot.Store(buildSnapshot([]Policy{}))
	return e
}

// LoadPolicies replaces the full policy set atomically
func (e *Engine) LoadPolicies(policies []Policy) error {
	newSnap := buildSnapshot(policies)
	e.snapshot.Store(newSnap)
	return nil
}

// Evaluate returns the decision for a given domain and the querying client.
//
// clientIP is the source address of the query (may be "host:port" as handed
// out by the dataplane, or a bare IP; empty when unknown). It is used to apply
// per-client policy scoping (I-014): a policy with a non-empty client scope is
// considered only for clients inside its ranges, while unscoped policies apply
// to everyone.
//
// Evaluation order:
//   - normalize domain
//   - exact-match/Bloom fast path (walks up parent domains) => decision
//   - scheduled policies only count while inside their active window (I-038)
//   - policies are further filtered to those in scope for this client (I-014)
//   - regex + wildcard slow path (only on exact miss) => decision
//   - otherwise => ALLOW
//
// The exact-match fast path returns immediately when it hits, so an exact rule
// always wins over regex/wildcard rules. Within the regex/wildcard slow path,
// the usual priority ordering applies (higher priority wins; tie => lexicographic ID).
func (e *Engine) Evaluate(domain string, clientIP string) (Decision, error) {
	d := normalizeDomain(domain)
	snap := e.snapshot.Load().(*PolicySnapshot)
	client := parseClientIP(clientIP)
	now := e.now()

	// Check exact match first, then walk up parent domains for subdomain matching.
	// e.g., www.godaddy.com → check www.godaddy.com, then godaddy.com.
	parts := strings.Split(d, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		if snap.Bloom != nil && !snap.Bloom.TestString(candidate) {
			continue
		}
		pols, ok := snap.Exact[candidate]
		if !ok || len(pols) == 0 {
			continue
		}
		// Drop scheduled policies that are outside their active window (I-038).
		// A policy inactive right now is treated as if it did not match, so
		// evaluation keeps walking up to any always-on parent-domain rule.
		active := filterActive(pols, now)
		if len(active) == 0 {
			continue
		}
		// Keep only policies whose client scope matches this client (I-014).
		// Unscoped policies always match (fast path in matchesClient). If
		// nothing is in scope at this level, keep walking up to parent domains
		// rather than stopping — a scoped rule on a subdomain must not mask a
		// broader rule on its parent for a different client.
		best := pickHighestPriorityScoped(snap, active, client)
		if best != nil {
			return policyDecision(best), nil
		}
	}

	// Slow path: no exact match. Evaluate wildcard and compiled-regex rules,
	// respecting the same priority ordering, schedule, and client-scope rules
	// as the exact path.
	if best := matchDynamic(snap, d, now, client); best != nil {
		return policyDecision(best), nil
	}

	return Decision{Action: ActionAllow}, nil
}

// matchDynamic returns the highest-priority active, in-scope policy whose
// wildcard or compiled regex rule matches d, or nil when nothing matches. A
// wildcard "*.example.com" matches the base domain ("example.com") and any
// subdomain of it. Scheduled policies (I-038) and client scoping (I-014) are
// filtered the same as the exact-match path above.
func matchDynamic(snap *PolicySnapshot, d string, now time.Time, client net.IP) *Policy {
	var candidates []*Policy
	for _, w := range snap.Wildcards {
		if d == w.base || strings.HasSuffix(d, "."+w.base) {
			candidates = append(candidates, w.policy)
		}
	}
	for _, r := range snap.Regexes {
		if r.re.MatchString(d) {
			candidates = append(candidates, r.policy)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	return pickHighestPriorityScoped(snap, filterActive(candidates, now), client)
}

// filterActive returns the policies that are active at the given instant. When
// none of the candidates carry a schedule it returns the input slice unchanged
// (no allocation), preserving the fast path for unscheduled policies.
func filterActive(pols []*Policy, now time.Time) []*Policy {
	scheduled := false
	for _, p := range pols {
		if p.sched != nil {
			scheduled = true
			break
		}
	}
	if !scheduled {
		return pols
	}

	out := make([]*Policy, 0, len(pols))
	for _, p := range pols {
		if p.sched.active(now) {
			out = append(out, p)
		}
	}
	return out
}

// pickHighestPriorityScoped selects the highest-priority policy from candidates
// that also applies to the given client, or nil if none are in scope.
func pickHighestPriorityScoped(snap *PolicySnapshot, candidates []*Policy, client net.IP) *Policy {
	var best *Policy
	for _, p := range candidates {
		if !snap.matchesClient(p, client) {
			continue
		}
		if best == nil || p.Priority > best.Priority {
			best = p
		} else if p.Priority == best.Priority && p.ID < best.ID {
			// deterministic tie-breaker: lexicographic ID
			best = p
		}
	}
	return best
}

// IsExplicitlyAllowed reports whether the domain is matched by a real policy
// whose action is ALLOW, applying the same schedule (I-038) and per-client
// scope (I-014) filters as Evaluate. Unlike Evaluate — which stops at the
// first domain level that has an active, in-scope decision and returns
// whatever the highest-priority policy there says — IsExplicitlyAllowed
// keeps walking the full match surface (exact-match parent domains, then
// wildcard/regex rules) and returns true as soon as ANY active, in-scope
// ALLOW policy matches anywhere in it, even when a higher-priority BLOCK
// policy also matches at the same level. It exists so callers can
// distinguish "allowed because an admin explicitly allowlisted it" from
// Evaluate's default ActionAllow (no policy matched at all) — e.g. to let an
// explicit ALLOW override a blocklist hit without changing how ALLOW vs
// BLOCK priority is resolved within Evaluate itself.
func (e *Engine) IsExplicitlyAllowed(domain string, clientIP string) bool {
	d := normalizeDomain(domain)
	snap := e.snapshot.Load().(*PolicySnapshot)
	client := parseClientIP(clientIP)
	now := e.now()

	parts := strings.Split(d, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		if snap.Bloom != nil && !snap.Bloom.TestString(candidate) {
			continue
		}
		pols, ok := snap.Exact[candidate]
		if !ok {
			continue
		}
		if hasScopedAllow(snap, filterActive(pols, now), client) {
			return true
		}
	}

	var dynamic []*Policy
	for _, w := range snap.Wildcards {
		if d == w.base || strings.HasSuffix(d, "."+w.base) {
			dynamic = append(dynamic, w.policy)
		}
	}
	for _, r := range snap.Regexes {
		if r.re.MatchString(d) {
			dynamic = append(dynamic, r.policy)
		}
	}
	return hasScopedAllow(snap, filterActive(dynamic, now), client)
}

// hasScopedAllow reports whether any policy in pols that is in scope for
// client has action ALLOW. Callers pass already schedule-filtered policies.
func hasScopedAllow(snap *PolicySnapshot, pols []*Policy, client net.IP) bool {
	for _, p := range pols {
		if !snap.matchesClient(p, client) {
			continue
		}
		if strings.ToUpper(p.Action) == "ALLOW" {
			return true
		}
	}
	return false
}

func policyDecision(p *Policy) Decision {
	if p == nil {
		return Decision{Action: ActionAllow}
	}
	var act Action
	switch strings.ToUpper(p.Action) {
	case "BLOCK":
		act = ActionDeny
	case "REDIRECT":
		act = ActionRedirect
	case "ALLOW":
		act = ActionAllow
	default:
		act = ActionAllow
	}
	return Decision{
		Action:     act,
		PolicyID:   p.ID,
		Category:   p.Category,
		RedirectIP: p.Redirect,
	}
}
