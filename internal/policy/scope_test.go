package policy

import "testing"

// TestEvaluate_ScopedPolicyMatchingClient verifies a client-scoped policy
// applies to a query from a client inside its range.
func TestEvaluate_ScopedPolicyMatchingClient(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "scoped", Action: "BLOCK", Priority: 100,
			Domains: []string{"ads.example.com"}, ClientCIDRs: []string{"192.168.1.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}

	d, err := e.Evaluate("ads.example.com", "192.168.1.50:5353")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny {
		t.Errorf("expected ActionDeny for in-scope client, got %v", d.Action)
	}
	if d.PolicyID != "scoped" {
		t.Errorf("expected policy ID scoped, got %q", d.PolicyID)
	}
}

// TestEvaluate_ScopedPolicyNonMatchingClient verifies a client-scoped policy
// does NOT apply to a query from a client outside its range (default Allow).
func TestEvaluate_ScopedPolicyNonMatchingClient(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "scoped", Action: "BLOCK", Priority: 100,
			Domains: []string{"ads.example.com"}, ClientCIDRs: []string{"192.168.1.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}

	d, err := e.Evaluate("ads.example.com", "10.0.0.5:1234")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for out-of-scope client, got %v", d.Action)
	}
}

// TestEvaluate_UnscopedPolicyAppliesToAll verifies an unscoped policy applies
// to every client, including one whose IP is unknown.
func TestEvaluate_UnscopedPolicyAppliesToAll(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "all", Action: "BLOCK", Priority: 100, Domains: []string{"ads.example.com"}},
	}); err != nil {
		t.Fatal(err)
	}

	for _, client := range []string{"192.168.1.50:53", "10.0.0.5:53", "", "not-an-ip"} {
		d, err := e.Evaluate("ads.example.com", client)
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != ActionDeny {
			t.Errorf("expected ActionDeny for unscoped policy with client %q, got %v", client, d.Action)
		}
	}
}

// TestEvaluate_ScopedPolicyUnknownClientIP verifies a scoped policy never
// matches when the client IP cannot be determined (fail-closed for scope).
func TestEvaluate_ScopedPolicyUnknownClientIP(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "scoped", Action: "BLOCK", Priority: 100,
			Domains: []string{"ads.example.com"}, ClientCIDRs: []string{"192.168.1.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}

	d, err := e.Evaluate("ads.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for scoped policy with unknown client, got %v", d.Action)
	}
}

// TestEvaluate_ScopeSingleHostIP verifies a bare host IP scope (no CIDR)
// matches only that exact client.
func TestEvaluate_ScopeSingleHostIP(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "host", Action: "BLOCK", Priority: 100,
			Domains: []string{"ads.example.com"}, ClientCIDRs: []string{"192.168.1.10"}},
	}); err != nil {
		t.Fatal(err)
	}

	if d, _ := e.Evaluate("ads.example.com", "192.168.1.10:5000"); d.Action != ActionDeny {
		t.Errorf("expected ActionDeny for exact host, got %v", d.Action)
	}
	if d, _ := e.Evaluate("ads.example.com", "192.168.1.11:5000"); d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for different host, got %v", d.Action)
	}
}

// TestEvaluate_MultipleClientsIndependent verifies two clients see independent
// decisions: a scoped block hits only one subnet, the other stays allowed,
// while an unscoped policy on a different domain hits both.
func TestEvaluate_MultipleClientsIndependent(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "kids-block", Action: "BLOCK", Priority: 100,
			Domains: []string{"social.example.com"}, ClientCIDRs: []string{"192.168.10.0/24"}},
		{ID: "global-block", Action: "BLOCK", Priority: 100,
			Domains: []string{"malware.example.com"}},
	}); err != nil {
		t.Fatal(err)
	}

	const kid = "192.168.10.5:53"
	const staff = "192.168.20.9:53"

	// Scoped rule: only the kids subnet is blocked on social.
	if d, _ := e.Evaluate("social.example.com", kid); d.Action != ActionDeny {
		t.Errorf("kid: expected social blocked, got %v", d.Action)
	}
	if d, _ := e.Evaluate("social.example.com", staff); d.Action != ActionAllow {
		t.Errorf("staff: expected social allowed, got %v", d.Action)
	}

	// Unscoped rule: both clients are blocked on malware.
	if d, _ := e.Evaluate("malware.example.com", kid); d.Action != ActionDeny {
		t.Errorf("kid: expected malware blocked, got %v", d.Action)
	}
	if d, _ := e.Evaluate("malware.example.com", staff); d.Action != ActionDeny {
		t.Errorf("staff: expected malware blocked, got %v", d.Action)
	}
}

// TestEvaluate_ScopeWalksToParentPolicy verifies that when a scoped policy on a
// subdomain does not apply to the client, evaluation still finds a broader
// unscoped policy on the parent domain rather than stopping early.
func TestEvaluate_ScopeWalksToParentPolicy(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "sub-scoped", Action: "REDIRECT", Priority: 100, Redirect: "1.2.3.4",
			Domains: []string{"api.example.com"}, ClientCIDRs: []string{"192.168.1.0/24"}},
		{ID: "parent-all", Action: "BLOCK", Priority: 100,
			Domains: []string{"example.com"}},
	}); err != nil {
		t.Fatal(err)
	}

	// Out-of-scope client: subdomain rule is skipped, parent BLOCK applies.
	d, err := e.Evaluate("api.example.com", "10.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionDeny || d.PolicyID != "parent-all" {
		t.Errorf("expected parent BLOCK for out-of-scope client, got action=%v id=%q", d.Action, d.PolicyID)
	}

	// In-scope client: subdomain REDIRECT wins (most specific match).
	d, err = e.Evaluate("api.example.com", "192.168.1.7:53")
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ActionRedirect || d.PolicyID != "sub-scoped" {
		t.Errorf("expected subdomain REDIRECT for in-scope client, got action=%v id=%q", d.Action, d.PolicyID)
	}
}

// TestEvaluate_ScopeIPv6 verifies IPv6 CIDR scoping works, including the
// bracketed host:port form handed out by the dataplane.
func TestEvaluate_ScopeIPv6(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.LoadPolicies([]Policy{
		{ID: "v6", Action: "BLOCK", Priority: 100,
			Domains: []string{"ads.example.com"}, ClientCIDRs: []string{"2001:db8::/32"}},
	}); err != nil {
		t.Fatal(err)
	}

	if d, _ := e.Evaluate("ads.example.com", "[2001:db8::1]:53"); d.Action != ActionDeny {
		t.Errorf("expected ActionDeny for in-scope IPv6 client, got %v", d.Action)
	}
	if d, _ := e.Evaluate("ads.example.com", "[2001:dead::1]:53"); d.Action != ActionAllow {
		t.Errorf("expected ActionAllow for out-of-scope IPv6 client, got %v", d.Action)
	}
}

// TestValidatePolicy_ClientScope verifies scope validation accepts valid
// IP/CIDR entries and rejects malformed ones.
func TestValidatePolicy_ClientScope(t *testing.T) {
	valid := &Policy{ID: "p", Action: "BLOCK",
		ClientCIDRs: []string{"192.168.1.0/24", "10.0.0.5", "2001:db8::/32"}}
	if err := ValidatePolicy(valid); err != nil {
		t.Errorf("expected valid client scope to pass, got %v", err)
	}

	bad := &Policy{ID: "p", Action: "BLOCK", ClientCIDRs: []string{"not-a-cidr"}}
	if err := ValidatePolicy(bad); err == nil {
		t.Error("expected invalid client scope to fail validation")
	}

	empty := &Policy{ID: "p", Action: "BLOCK", ClientCIDRs: []string{"  "}}
	if err := ValidatePolicy(empty); err == nil {
		t.Error("expected empty client scope entry to fail validation")
	}
}
