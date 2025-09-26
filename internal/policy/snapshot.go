package policy

import (
	"strings"

	"github.com/willf/bloom"
)

type PolicySnapshot struct {
	Bloom *bloom.BloomFilter
	Exact map[string][]*Policy // exact domain to policies
}

func buildSnapshot(policies []Policy) *PolicySnapshot {
	exact := make(map[string][]*Policy)
	totalDomains := 0

	// normalize domains and count total
	for i := range policies {
		for _, d := range policies[i].Domains {
			normalized := normalizeDomain(d)
			totalDomains++
			if strings.Contains(normalized, "*") {
				// TODO: wildcard handling later - for now still add to bloom
				continue
			}
			exact[normalized] = append(exact[normalized], &policies[i])
		}
		for _, rx := range policies[i].Regexes {
			totalDomains++
			_ = rx
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
		Exact: exact,
		Bloom: bf,
	}
}
