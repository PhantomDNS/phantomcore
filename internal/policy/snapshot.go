package policy

import (
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
}

func buildSnapshot(policies []Policy) *PolicySnapshot {
	exact := make(map[string][]*Policy)
	var wildcards []wildcardRule
	var regexes []compiledRegexRule
	totalDomains := 0

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
		for _, d := range policies[i].Domains {
			bf.AddString(normalizeDomain(d))
		}
		for _, r := range policies[i].Regexes {
			bf.AddString(r)
		}
	}

	return &PolicySnapshot{
		Exact:     exact,
		Bloom:     bf,
		Regexes:   regexes,
		Wildcards: wildcards,
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
