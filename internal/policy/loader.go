package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type policyFile struct {
	Policies []Policy `json:"policies"`
}

func LoadPolicyFromFile(path string) ([]Policy, error) {
	if path == "" {
		return nil, fmt.Errorf("No file path provided")
	}

	f, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("Unable to read file")
	}

	var pf policyFile

	if err := json.Unmarshal(f, &pf); err != nil {
		return nil, fmt.Errorf("Failed to marshal, check JSON syntax")
	}

	for i := range pf.Policies {
		if err := ValidatePolicy(&pf.Policies[i]); err != nil {
			return nil, fmt.Errorf("Invalid policy %d: %v", i, err)
		}
		// normalize domains
		for j := range pf.Policies[i].Domains {
			pf.Policies[i].Domains[j] = normalizeDomain(pf.Policies[i].Domains[j])
		}
		// compile regexes to ensure validity
		for _, r := range pf.Policies[i].Regexes {
			if _, err := regexp.Compile(r); err != nil {
				return nil, fmt.Errorf("policy %s: invalid regex %q: %w", pf.Policies[i].ID, r, err)
			}
		}
	}

	return pf.Policies, nil
}

func ValidatePolicy(p *Policy) error {
	if p == nil {
		return fmt.Errorf("policy nil")
	}
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("id required")
	}
	if strings.TrimSpace(p.Action) == "" {
		return fmt.Errorf("action required")
	}
	switch strings.ToUpper(p.Action) {
	case "BLOCK", "ALLOW", "REDIRECT":
	default:
		return fmt.Errorf("unsupported action %q", p.Action)
	}
	// domains optional (regex can be used), but if domains present ensure valid-looking values
	for _, d := range p.Domains {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("empty domain in policy %s", p.ID)
		}
	}
	return nil
}
