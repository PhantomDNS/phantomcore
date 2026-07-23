package policy

import (
	"net"
	"regexp"
	"strings"

	"github.com/willf/bloom"
)

// compiledRegexRule pairs a pre-compiled regex with the policy that owns it.
type compiledRegexRule struct {
	re     *regexp.Regexp
	policy *Policy
}

// wildcardRule holds a wildcard entry (e.g. "*.example.com") reduced to its
// base domain ("example.com") plus the policy that owns it.
type wildcardRule struct {
	base   string
	policy *Policy
}

type PolicySnapshot struct {
	Bloom *bloom.BloomFilter
	Exact map[string][]*Policy // exact domain to policies

	// Regexes and Wildcards are evaluated only AFTER the exact/Bloom fast
	// path misses, so the hot path stays untouched. Regexes are compiled
	// once at snapshot-build time and cached here.
	Regexes   []compiledRegexRule
	Wildcards []wildcardRule

	// clientNets holds the parsed client-scope ranges for each scoped policy,
	// keyed by policy ID. It is precomputed once at snapshot-build time so
	// per-query client matching never re-parses CIDR strings. Unscoped
	// policies are absent from this map (see matchesClient). (I-014)
	clientNets map[string][]*net.IPNet
}

func buildSnapshot(policies []Policy) *PolicySnapshot {
	exact := make(map[string][]*Policy)
	var wildcards []wildcardRule
	var regexes []compiledRegexRule
	clientNets := make(map[string][]*net.IPNet)
	totalDomains := 0

	// Precompute each policy's schedule once (I-038). A nil result means the
	// policy is always active. Malformed schedules should have been rejected at
	// write time; here we fail safe by treating them as always-on rather than
	// dropping the policy from the snapshot.
	for i := range policies {
		cs, err := compileSchedule(&policies[i])
		if err != nil {
			cs = nil
		}
		policies[i].sched = cs
	}

	// normalize domains and count total
	for i := range policies {
		p := &policies[i]
		for _, d := range p.Domains {
			normalized := normalizeDomain(d)
			totalDomains++
			if strings.Contains(normalized, "*") {
				// wildcard entry, e.g. "*.example.com"
				if base := wildcardBase(normalized); base != "" {
					wildcards = append(wildcards, wildcardRule{base: base, policy: p})
				}
				continue
			}
			exact[normalized] = append(exact[normalized], p)
		}
		for _, rx := range p.Regexes {
			totalDomains++
			re, err := regexp.Compile(rx)
			if err != nil {
				// Invalid regex: skip safely. Load-time validation already
				// rejects these, but guard here so a bad rule that reaches
				// the snapshot never crashes the query path.
				continue
			}
			regexes = append(regexes, compiledRegexRule{re: re, policy: p})
		}
		// Precompute parsed client-scope ranges for scoped policies so
		// per-query matching is allocation- and parse-free. Invalid entries
		// are skipped here; the loader/control-plane validate on ingest, so a
		// bad range means "no valid ranges" and the scoped policy simply never
		// matches (fail-closed for scope, not for the whole policy set).
		for _, c := range p.ClientCIDRs {
			if n, err := parseClientScope(c); err == nil {
				clientNets[p.ID] = append(clientNets[p.ID], n)
			}
		}
	}

	// build the bloom filter
	fpRate := 0.0001
	if totalDomains == 0 {
		// small default
		totalDomains = 1
	}
	bf := bloom.NewWithEstimates(uint(totalDomains), fpRate)
	for d := range exact {
		bf.AddString(d)
	}

	// add raw domains with wildcard and plain regex tokens as strings
	for i := range policies {
		p := &policies[i]
		for _, d := range p.Domains {
			bf.AddString(normalizeDomain(d))
		}
		for _, r := range p.Regexes {
			bf.AddString(r)
		}
	}

	return &PolicySnapshot{
		Exact:      exact,
		Bloom:      bf,
		Regexes:    regexes,
		Wildcards:  wildcards,
		clientNets: clientNets,
	}
}

// wildcardBase reduces a leading-label wildcard pattern to its base domain.
// "*.example.com" => "example.com". Returns "" for unsupported patterns.
func wildcardBase(pattern string) string {
	if strings.HasPrefix(pattern, "*.") {
		return pattern[2:]
	}
	return ""
}
