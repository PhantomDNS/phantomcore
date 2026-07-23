package policy

import (
	"strings"
	"sync/atomic"
)

type Engine struct {
	snapshot atomic.Value // holds *Snapshot
}

func NewPolicyEngine() *Engine {
	e := &Engine{}
	e.snapshot.Store(buildSnapshot([]Policy{}))
	return e
}

// LoadPolicies replaces the full policy set atomically
func (e *Engine) LoadPolicies(policies []Policy) error {
	newSnap := buildSnapshot(policies)
	e.snapshot.Store(newSnap)
	return nil
}

// Evaluate returns the decision for given domain and context.
// Evaluation order:
//   - normalize domain
//   - exact-match/Bloom fast path (walks up parent domains) => decision
//   - regex + wildcard slow path (only on exact miss) => decision
//   - otherwise => ALLOW
//
// The exact-match fast path returns immediately when it hits, so an exact rule
// always wins over regex/wildcard rules. Within the regex/wildcard slow path,
// the usual priority ordering applies (higher priority wins; tie => lexicographic ID).
func (e *Engine) Evaluate(domain string) (Decision, error) {
	d := normalizeDomain(domain)
	snap := e.snapshot.Load().(*PolicySnapshot)

	// Check exact match first, then walk up parent domains for subdomain matching.
	// e.g., www.godaddy.com → check www.godaddy.com, then godaddy.com.
	// This is the hot path and is intentionally left untouched.
	parts := strings.Split(d, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		if snap.Bloom != nil && !snap.Bloom.TestString(candidate) {
			continue
		}
		if pols, ok := snap.Exact[candidate]; ok && len(pols) > 0 {
			best := pickHighestPriority(pols)
			return policyDecision(best), nil
		}
	}

	// Slow path: no exact match. Evaluate wildcard and compiled-regex rules,
	// respecting the same priority ordering as the exact path.
	if best := matchDynamic(snap, d); best != nil {
		return policyDecision(best), nil
	}

	return Decision{Action: ActionAllow}, nil
}

// matchDynamic returns the highest-priority policy whose wildcard or compiled
// regex rule matches d, or nil when nothing matches. A wildcard "*.example.com"
// matches the base domain ("example.com") and any subdomain of it.
func matchDynamic(snap *PolicySnapshot, d string) *Policy {
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
	return pickHighestPriority(candidates)
}

// pickHighestPriority returns the matching policy with highest priority (deterministic).
func pickHighestPriority(candidates []*Policy) *Policy {
	var best *Policy
	for _, p := range candidates {
		if best == nil || p.Priority > best.Priority {
			best = p
		} else if p.Priority == best.Priority {
			// deterministic tie-breaker: lexicographic ID
			if p.ID < best.ID {
				best = p
			}
		}
	}
	return best
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
