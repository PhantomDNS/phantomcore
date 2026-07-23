package policy

import (
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  Example.COM.  ", "example.com"},
		{"already.normal", "already.normal"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeDomain(tt.input); got != tt.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEvaluate_AllowByDefault(t *testing.T) {
	e := NewPolicyEngine()
	d, err := e.Evaluate("unknown.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %v", d.Action)
	}
}

func TestEvaluate_BlockExactDomain(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "block-ads", Action: "BLOCK", Priority: 100, Domains: []string{"ads.example.com"}},
	})

	d, err := e.Evaluate("ads.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny {
		t.Errorf("expected ActionDeny, got %v", d.Action)
	}
	if d.PolicyID != "block-ads" {
		t.Errorf("expected policy ID block-ads, got %q", d.PolicyID)
	}
}

func TestEvaluate_CaseInsensitive(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "p1", Action: "BLOCK", Priority: 100, Domains: []string{"ADS.Example.COM"}},
	})

	d, err := e.Evaluate("ads.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny {
		t.Errorf("expected ActionDeny for case-insensitive match")
	}
}

func TestEvaluate_TrailingDotNormalized(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "p1", Action: "BLOCK", Priority: 100, Domains: []string{"blocked.com"}},
	})

	d, err := e.Evaluate("blocked.com.", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny {
		t.Errorf("expected ActionDeny for domain with trailing dot")
	}
}

func TestEvaluate_Redirect(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "redir", Action: "REDIRECT", Priority: 100, Redirect: "1.2.3.4", Domains: []string{"redirect.me"}},
	})

	d, err := e.Evaluate("redirect.me", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionRedirect {
		t.Errorf("expected ActionRedirect, got %v", d.Action)
	}
	if d.RedirectIP != "1.2.3.4" {
		t.Errorf("expected redirect IP 1.2.3.4, got %q", d.RedirectIP)
	}
}

func TestEvaluate_HighestPriorityWins(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "low", Action: "ALLOW", Priority: 10, Domains: []string{"test.com"}},
		{ID: "high", Action: "BLOCK", Priority: 200, Domains: []string{"test.com"}},
	})

	d, err := e.Evaluate("test.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny {
		t.Errorf("expected highest priority (BLOCK) to win, got %v", d.Action)
	}
	if d.PolicyID != "high" {
		t.Errorf("expected policy ID 'high', got %q", d.PolicyID)
	}
}

func TestEvaluate_TieBreakByID(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "zzz", Action: "ALLOW", Priority: 100, Domains: []string{"tie.com"}},
		{ID: "aaa", Action: "BLOCK", Priority: 100, Domains: []string{"tie.com"}},
	})

	d, err := e.Evaluate("tie.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.PolicyID != "aaa" {
		t.Errorf("expected lexicographically first ID 'aaa' on tie, got %q", d.PolicyID)
	}
}

func TestEvaluate_BloomNegativeShortCircuit(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "p1", Action: "BLOCK", Priority: 100, Domains: []string{"blocked.com"}},
	})

	// Domain not in bloom filter should be allowed without hitting exact map
	d, err := e.Evaluate("notblocked.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for domain not in bloom filter")
	}
}

func TestEvaluate_MultipleDomainsSamePolicy(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "multi", Action: "BLOCK", Priority: 100, Domains: []string{"a.com", "b.com", "c.com"}},
	})

	for _, domain := range []string{"a.com", "b.com", "c.com"} {
		d, err := e.Evaluate(domain, "")
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != ActionDeny {
			t.Errorf("expected %s to be blocked", domain)
		}
	}
}

func TestEvaluate_EmptyPolicies(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{})

	d, err := e.Evaluate("anything.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow with empty policies")
	}
}

func TestPolicyDecision_UnknownAction(t *testing.T) {
	d := policyDecision(&Policy{ID: "x", Action: "UNKNOWN_ACTION"})
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for unknown action, got %v", d.Action)
	}
}

func TestPolicyDecision_Nil(t *testing.T) {
	d := policyDecision(nil)
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for nil policy, got %v", d.Action)
	}
}

func TestEvaluate_BlockByRegex(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "rx-block", Action: "BLOCK", Priority: 100, Regexes: []string{`.*\.doubleclick\.net$`}},
	})

	d, err := e.Evaluate("ads.doubleclick.net", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny {
		t.Errorf("expected ActionDeny for regex match, got %v", d.Action)
	}
	if d.PolicyID != "rx-block" {
		t.Errorf("expected policy ID rx-block, got %q", d.PolicyID)
	}

	// Non-matching domain should fall through to ALLOW.
	d, err = e.Evaluate("safe.example.org", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for non-matching domain, got %v", d.Action)
	}
}

func TestEvaluate_RegexAllowOverridesByPriority(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "rx-block", Action: "BLOCK", Priority: 10, Regexes: []string{`.*\.tracking\.com$`}},
		{ID: "rx-allow", Action: "ALLOW", Priority: 100, Regexes: []string{`.*\.tracking\.com$`}},
	})

	d, err := e.Evaluate("beacon.tracking.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected higher-priority ALLOW regex to win, got %v", d.Action)
	}
	if d.PolicyID != "rx-allow" {
		t.Errorf("expected policy ID rx-allow, got %q", d.PolicyID)
	}
}

func TestEvaluate_RegexTieBreakByID(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "zzz-rx", Action: "ALLOW", Priority: 50, Regexes: []string{`^tie\.rx$`}},
		{ID: "aaa-rx", Action: "BLOCK", Priority: 50, Regexes: []string{`^tie\.rx$`}},
	})

	d, err := e.Evaluate("tie.rx", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.PolicyID != "aaa-rx" {
		t.Errorf("expected lexicographically first ID 'aaa-rx' on tie, got %q", d.PolicyID)
	}
	if d.Action != ActionDeny {
		t.Errorf("expected ActionDeny from tie-break winner, got %v", d.Action)
	}
}

func TestEvaluate_WildcardMatchesSubdomains(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "wild", Action: "BLOCK", Priority: 100, Domains: []string{"*.example.com"}},
	})

	// Wildcard matches the base domain and any depth of subdomain.
	for _, domain := range []string{"example.com", "sub.example.com", "a.b.example.com"} {
		d, err := e.Evaluate(domain, "")
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != ActionDeny {
			t.Errorf("expected %s to be blocked by wildcard, got %v", domain, d.Action)
		}
		if d.PolicyID != "wild" {
			t.Errorf("expected policy ID wild for %s, got %q", domain, d.PolicyID)
		}
	}

	// Unrelated domains must not match.
	for _, domain := range []string{"notexample.com", "example.com.evil.net", "other.org"} {
		d, err := e.Evaluate(domain, "")
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != ActionAllow {
			t.Errorf("expected %s to be allowed (no wildcard match), got %v", domain, d.Action)
		}
	}
}

func TestEvaluate_WildcardPriority(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "wild-block", Action: "BLOCK", Priority: 10, Domains: []string{"*.corp.com"}},
		{ID: "wild-allow", Action: "ALLOW", Priority: 100, Domains: []string{"*.corp.com"}},
	})

	d, err := e.Evaluate("intra.corp.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow || d.PolicyID != "wild-allow" {
		t.Errorf("expected higher-priority wildcard ALLOW to win, got action=%v id=%q", d.Action, d.PolicyID)
	}
}

func TestEvaluate_ExactWinsOverRegex(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "exact", Action: "BLOCK", Priority: 10, Domains: []string{"exact.com"}},
		// Catch-all regex at much higher priority; exact fast path must still win.
		{ID: "rx-all", Action: "ALLOW", Priority: 999, Regexes: []string{`.*`}},
	})

	d, err := e.Evaluate("exact.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny || d.PolicyID != "exact" {
		t.Errorf("expected exact-match fast path to win, got action=%v id=%q", d.Action, d.PolicyID)
	}

	// A domain with no exact match falls through to the regex slow path.
	d, err = e.Evaluate("anything.else", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow || d.PolicyID != "rx-all" {
		t.Errorf("expected regex slow path to match, got action=%v id=%q", d.Action, d.PolicyID)
	}
}

func TestEvaluate_InvalidRegexDoesNotCrash(t *testing.T) {
	e := NewPolicyEngine()
	// Bad regex reaches the snapshot directly (LoadPolicies skips load-time
	// validation); it must be skipped, and valid rules must still work.
	e.LoadPolicies([]Policy{
		{ID: "bad-rx", Action: "BLOCK", Priority: 100, Regexes: []string{`[invalid(`}},
		{ID: "good-rx", Action: "BLOCK", Priority: 100, Regexes: []string{`^good\.net$`}},
	})

	// The invalid regex is skipped; querying anything must not panic.
	d, err := e.Evaluate("harmless.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow (invalid regex skipped), got %v", d.Action)
	}

	// The valid regex alongside it still matches.
	d, err = e.Evaluate("good.net", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny || d.PolicyID != "good-rx" {
		t.Errorf("expected valid regex to still match, got action=%v id=%q", d.Action, d.PolicyID)
	}
}

func TestEvaluate_ExactStillWorksWithDynamicRulesPresent(t *testing.T) {
	e := NewPolicyEngine()
	e.LoadPolicies([]Policy{
		{ID: "exact-block", Action: "BLOCK", Priority: 100, Domains: []string{"ads.example.com"}},
		{ID: "wild", Action: "BLOCK", Priority: 100, Domains: []string{"*.tracker.net"}},
		{ID: "rx", Action: "BLOCK", Priority: 100, Regexes: []string{`^evil\.io$`}},
	})

	d, err := e.Evaluate("ads.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny || d.PolicyID != "exact-block" {
		t.Errorf("expected exact match to still work with regex/wildcard present, got action=%v id=%q", d.Action, d.PolicyID)
	}
}

func TestActionString(t *testing.T) {
	tests := []struct {
		a    Action
		want string
	}{
		{ActionAllow, "allow"},
		{ActionDeny, "block"},
		{ActionRedirect, "redirect"},
		{Action(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.a.String(); got != tt.want {
			t.Errorf("Action(%d).String() = %q, want %q", tt.a, got, tt.want)
		}
	}
}
