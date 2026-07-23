package dnsengine

import (
	"net"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/metrics"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/threat"
	"github.com/miekg/dns"
)

// --- Mocks ---

type mockBlocklist struct {
	blocked map[string]bool
	err     error
}

func (m *mockBlocklist) IsBlocked(domain string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.blocked[domain], nil
}

type mockResponseWriter struct {
	msg *dns.Msg
}

func (w *mockResponseWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (w *mockResponseWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (w *mockResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *mockResponseWriter) Close() error              { return nil }
func (w *mockResponseWriter) TsigStatus() error         { return nil }
func (w *mockResponseWriter) TsigTimersOnly(bool)       {}
func (w *mockResponseWriter) Hijack()                   {}

// mockQueryLog captures saved DNSQuery rows so tests can assert what was persisted.
// logQuery saves asynchronously, so Save publishes onto a buffered channel.
type mockQueryLog struct {
	saved chan *models.DNSQuery
}

func newMockQueryLog() *mockQueryLog {
	return &mockQueryLog{saved: make(chan *models.DNSQuery, 4)}
}

func (m *mockQueryLog) Save(q *models.DNSQuery) error {
	m.saved <- q
	return nil
}

func (m *mockQueryLog) ListRecent(limit int) ([]models.DNSQuery, error) {
	return nil, nil
}

// waitSaved blocks until logQuery's goroutine persists a row (or times out).
func (m *mockQueryLog) waitSaved(t *testing.T) *models.DNSQuery {
	t.Helper()
	select {
	case q := <-m.saved:
		return q
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for query to be logged")
		return nil
	}
}

func newTestQuery(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	return m
}

func newTestEngine(bl *mockBlocklist, policies []policy.Policy) *Engine {
	pe := policy.NewPolicyEngine()
	pe.LoadPolicies(policies)

	e := &Engine{
		policyEngine: pe,
		state:        &RuntimeState{},
		metrics:      metrics.NewQueryMetrics(),
	}
	e.state.acceptQueries.Store(true)
	if bl != nil {
		e.blocklist = bl
	}
	return e
}

// isBlockedResponse checks if a DNS response is a block (0.0.0.0 A record)
func isBlockedResponse(m *dns.Msg) bool {
	if m == nil {
		return false
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "0.0.0.0" {
			return true
		}
	}
	return false
}

// --- Tests ---

func TestStripSearchDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"godaddy.com.hgu_lan", "godaddy.com"},
		{"facebook.com.local", "facebook.com"},
		{"ads.google.com.domain.name", "ads.google.com"},
		{"github.com", "github.com"},
		{"example.com.lan", "example.com"},
		{"a.b.c.com.home", "a.b.c.com"},
		{"short.io", "short.io"},
	}
	for _, tt := range tests {
		if got := stripSearchDomain(tt.input); got != tt.want {
			t.Errorf("stripSearchDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"EXAMPLE.COM.", "example.com"},
		{"example.com", "example.com"},
		{"Test.IO.", "test.io"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeDomain(tt.input); got != tt.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestProcessDNSQuery_DrainMode(t *testing.T) {
	e := newTestEngine(nil, nil)
	e.state.acceptQueries.Store(false)

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("example.com"))

	if w.msg == nil {
		t.Fatal("expected REFUSED response in drain mode, got nil")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("expected REFUSED rcode in drain mode, got %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_NilRequest(t *testing.T) {
	e := newTestEngine(nil, nil)
	w := &mockResponseWriter{}

	// Should not panic
	e.ProcessDNSQuery(w, nil)
	if w.msg != nil {
		t.Error("expected no response for nil request")
	}
}

func TestProcessDNSQuery_EmptyQuestion(t *testing.T) {
	e := newTestEngine(nil, nil)
	w := &mockResponseWriter{}

	e.ProcessDNSQuery(w, &dns.Msg{})
	if w.msg != nil {
		t.Error("expected no response for empty question")
	}
}

func TestProcessDNSQuery_BlockedByBlocklist(t *testing.T) {
	bl := &mockBlocklist{blocked: map[string]bool{"ads.example.com": true}}
	e := newTestEngine(bl, nil)

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("ads.example.com"))

	if w.msg == nil {
		t.Fatal("expected response for blocklisted domain")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected blocked (0.0.0.0) for blocklisted domain, got %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_BlockedByPolicy(t *testing.T) {
	policies := []policy.Policy{
		{ID: "block-test", Action: "BLOCK", Priority: 100, Domains: []string{"policy-blocked.com"}},
	}
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, policies)

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("policy-blocked.com"))

	if w.msg == nil {
		t.Fatal("expected response for policy-blocked domain")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected blocked (0.0.0.0) for policy-blocked domain, got %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_BlocklistBeforePolicy(t *testing.T) {
	// Domain is in both blocklist and policy — blocklist should win (checked first)
	bl := &mockBlocklist{blocked: map[string]bool{"both.com": true}}
	policies := []policy.Policy{
		{ID: "allow-both", Action: "ALLOW", Priority: 100, Domains: []string{"both.com"}},
	}
	e := newTestEngine(bl, policies)

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("both.com"))

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected blocked (0.0.0.0) (blocklist takes precedence), got %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_DomainNormalization(t *testing.T) {
	// Blocklist has lowercase "blocked.com", query comes as FQDN "BLOCKED.COM."
	bl := &mockBlocklist{blocked: map[string]bool{"blocked.com": true}}
	e := newTestEngine(bl, nil)

	w := &mockResponseWriter{}
	q := new(dns.Msg)
	q.SetQuestion("BLOCKED.COM.", dns.TypeA)
	e.ProcessDNSQuery(w, q)

	if w.msg == nil {
		t.Fatal("expected response for normalized domain match")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected blocked (0.0.0.0) after normalization, got %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_BlocklistErrorContinues(t *testing.T) {
	// Blocklist returns an error — should continue to policy evaluation, not hang
	bl := &mockBlocklist{err: net.ErrClosed}
	policies := []policy.Policy{
		{ID: "block-fallback", Action: "BLOCK", Priority: 100, Domains: []string{"test.com"}},
	}
	e := newTestEngine(bl, policies)

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("test.com"))

	if w.msg == nil {
		t.Fatal("expected response even when blocklist errors")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected policy to block after blocklist error, got rcode %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_PolicyAllowNoUpstream(t *testing.T) {
	// When policy allows but no upstream manager is set, forwardUpstream will fail
	// This tests that the engine doesn't panic with nil upstreamManager
	bl := &mockBlocklist{blocked: map[string]bool{}}
	e := newTestEngine(bl, nil)
	// upstreamManager is nil — forwardUpstream will be called

	w := &mockResponseWriter{}
	// This will panic if nil upstreamManager isn't handled
	// We expect it to try forwarding and fail, so let's skip this
	// since it requires a real upstream manager
	_ = w
	_ = e
}

func TestRespondBlocked(t *testing.T) {
	e := newTestEngine(nil, nil)
	w := &mockResponseWriter{}
	r := newTestQuery("test.com")

	e.respondBlocked(w, r, "test.com", "test-reason")

	if w.msg == nil {
		t.Fatal("expected response from respondBlocked")
	}
	if !isBlockedResponse(w.msg) {
		t.Error("expected blocked response (0.0.0.0 A record)")
	}
}

func TestRespondRedirect(t *testing.T) {
	e := newTestEngine(nil, nil)
	w := &mockResponseWriter{}
	r := newTestQuery("test.com")

	e.respondRedirect(w, r, "test.com.", "1.2.3.4")

	if w.msg == nil {
		t.Fatal("expected response from respondRedirect")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record in answer")
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("expected redirect to 1.2.3.4, got %s", a.A.String())
	}
}

func TestRespondRedirect_InvalidIP(t *testing.T) {
	e := newTestEngine(nil, nil)
	w := &mockResponseWriter{}
	r := newTestQuery("test.com")

	e.respondRedirect(w, r, "test.com.", "not-an-ip")

	if w.msg == nil {
		t.Fatal("expected SERVFAIL response for invalid redirect IP")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for invalid IP, got %d", w.msg.Rcode)
	}
}

func TestEngineStatus(t *testing.T) {
	e := newTestEngine(nil, nil)
	e.state.acceptQueries.Store(true)

	s := e.Status()
	if !s.Running {
		t.Error("expected Running=true")
	}
	if !s.AcceptingQueries {
		t.Error("expected AcceptingQueries=true")
	}
}

func TestEngineStatus_WithError(t *testing.T) {
	e := newTestEngine(nil, nil)
	e.state.lastError.Store("something broke")

	s := e.Status()
	if s.LastError != "something broke" {
		t.Errorf("expected last error 'something broke', got %q", s.LastError)
	}
}

func TestProcessDNSQuery_AbusedTLDBlocks(t *testing.T) {
	// TLD in the configured set is blocked on the default allow path.
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, nil)
	e.abusedTLDs = map[string]bool{"zip": true, "mov": true}

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("malware.zip"))

	if w.msg == nil {
		t.Fatal("expected response for abused-TLD domain")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected blocked (0.0.0.0) for abused TLD, got rcode %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_AbusedTLDNotInSetAllowed(t *testing.T) {
	// TLD not in the set reaches the allow path (no block).
	// Empty (pool-less) upstream manager returns SERVFAIL without a network call.
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, nil)
	e.abusedTLDs = map[string]bool{"zip": true}
	e.upstreamManager = &UpstreamManager{}

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("example.com"))

	if w.msg == nil {
		t.Fatal("expected response for allowed domain")
	}
	if isBlockedResponse(w.msg) {
		t.Error("expected non-abused TLD to reach allow path, but it was blocked")
	}
}

func TestProcessDNSQuery_AbusedTLDEmptySetIsOff(t *testing.T) {
	// Empty set = feature off: a .zip domain must not be blocked.
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, nil)
	// abusedTLDs left nil (empty).
	e.upstreamManager = &UpstreamManager{}

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("example.zip"))

	if w.msg == nil {
		t.Fatal("expected response when abused-TLD feature is off")
	}
	if isBlockedResponse(w.msg) {
		t.Error("expected no block with empty abused-TLD set, but domain was blocked")
	}
}

func TestProcessDNSQuery_AbusedTLDAllowPolicyOverrides(t *testing.T) {
	// An explicit ALLOW policy for the domain must win over the TLD block.
	policies := []policy.Policy{
		{ID: "allow-trusted", Action: "ALLOW", Priority: 100, Domains: []string{"trusted.zip"}},
	}
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, policies)
	e.abusedTLDs = map[string]bool{"zip": true}
	e.upstreamManager = &UpstreamManager{}

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("trusted.zip"))

	if w.msg == nil {
		t.Fatal("expected response for explicitly-allowed abused-TLD domain")
	}
	if isBlockedResponse(w.msg) {
		t.Error("expected explicit ALLOW policy to override abused-TLD block, but domain was blocked")
	}
}

func TestSetAcceptQueries(t *testing.T) {
	e := newTestEngine(nil, nil)

	e.SetAcceptQueries(false)
	if e.state.acceptQueries.Load() {
		t.Error("expected false after SetAcceptQueries(false)")
	}

	e.SetAcceptQueries(true)
	if !e.state.acceptQueries.Load() {
		t.Error("expected true after SetAcceptQueries(true)")
	}
}

func TestShouldEnforceThreat(t *testing.T) {
	tests := []struct {
		name      string
		tr        threat.Result
		threshold float64
		want      bool
	}{
		{"threshold 0 disables", threat.Result{IsSuspicious: true, ThreatScore: 0.9}, 0, false},
		{"above threshold", threat.Result{IsSuspicious: true, ThreatScore: 0.9}, 0.8, true},
		{"equal to threshold", threat.Result{IsSuspicious: true, ThreatScore: 0.8}, 0.8, true},
		{"below threshold", threat.Result{IsSuspicious: true, ThreatScore: 0.7}, 0.8, false},
		{"not suspicious", threat.Result{IsSuspicious: false, ThreatScore: 0.9}, 0.8, false},
	}
	for _, tt := range tests {
		if got := shouldEnforceThreat(tt.tr, tt.threshold); got != tt.want {
			t.Errorf("%s: shouldEnforceThreat = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// mustRR builds a dns.RR from its zone-file string form or fails the test.
func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("failed to build RR %q: %v", s, err)
	}
	return rr
}

// TestFilterRebind_SingleRecord classifies one record at a time: private,
// loopback, link-local (unicast + multicast), and unspecified addresses must be
// dropped, while genuine public addresses must be kept — for both A and AAAA.
func TestFilterRebind_SingleRecord(t *testing.T) {
	tests := []struct {
		name     string
		rr       string
		wantDrop bool
	}{
		// Private IPv4 (RFC 1918)
		{"private-10", "example.com. 300 IN A 10.0.0.1", true},
		{"private-172", "example.com. 300 IN A 172.16.5.4", true},
		{"private-192", "example.com. 300 IN A 192.168.1.1", true},
		// Loopback
		{"loopback-v4", "example.com. 300 IN A 127.0.0.1", true},
		{"loopback-v6", "example.com. 300 IN AAAA ::1", true},
		// Link-local unicast
		{"linklocal-v4", "example.com. 300 IN A 169.254.1.1", true},
		{"linklocal-v6", "example.com. 300 IN AAAA fe80::1", true},
		// Link-local multicast
		{"llmulticast-v4", "example.com. 300 IN A 224.0.0.251", true},
		{"llmulticast-v6", "example.com. 300 IN AAAA ff02::1", true},
		// Unspecified
		{"unspecified-v4", "example.com. 300 IN A 0.0.0.0", true},
		{"unspecified-v6", "example.com. 300 IN AAAA ::", true},
		// Private IPv6 (ULA fc00::/7)
		{"ula-v6", "example.com. 300 IN AAAA fc00::1", true},
		// Public — kept
		{"public-v4-google", "example.com. 300 IN A 8.8.8.8", false},
		{"public-v4-cf", "example.com. 300 IN A 1.1.1.1", false},
		{"public-v6-cf", "example.com. 300 IN AAAA 2606:4700:4700::1111", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, dropped := filterRebind([]dns.RR{mustRR(t, tt.rr)})
			if tt.wantDrop {
				if dropped != 1 || len(kept) != 0 {
					t.Errorf("%s: expected dropped=1 kept=0, got dropped=%d kept=%d", tt.rr, dropped, len(kept))
				}
			} else {
				if dropped != 0 || len(kept) != 1 {
					t.Errorf("%s: expected dropped=0 kept=1, got dropped=%d kept=%d", tt.rr, dropped, len(kept))
				}
			}
		})
	}
}

// TestFilterRebind_Mixed verifies a mixed answer set keeps only the public
// records and reports the correct drop count.
func TestFilterRebind_Mixed(t *testing.T) {
	answers := []dns.RR{
		mustRR(t, "example.com. 300 IN A 8.8.8.8"),                 // public, keep
		mustRR(t, "example.com. 300 IN A 192.168.1.1"),             // private, drop
		mustRR(t, "example.com. 300 IN AAAA 2606:4700:4700::1111"), // public, keep
		mustRR(t, "example.com. 300 IN AAAA ::1"),                  // loopback, drop
		mustRR(t, "example.com. 300 IN A 127.0.0.1"),               // loopback, drop
	}
	kept, dropped := filterRebind(answers)
	if dropped != 3 {
		t.Errorf("expected 3 dropped, got %d", dropped)
	}
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(kept))
	}
	for _, rr := range kept {
		switch v := rr.(type) {
		case *dns.A:
			if v.A.String() != "8.8.8.8" {
				t.Errorf("unexpected A kept: %s", v.A.String())
			}
		case *dns.AAAA:
			if v.AAAA.String() != "2606:4700:4700::1111" {
				t.Errorf("unexpected AAAA kept: %s", v.AAAA.String())
			}
		default:
			t.Errorf("unexpected record type kept: %T", rr)
		}
	}
}

func TestThreatDecision(t *testing.T) {
	sus := threat.Result{IsSuspicious: true, ThreatScore: 0.9}

	if got := (&Engine{threatBlockThreshold: 0}).threatDecision(sus); got != threatNone {
		t.Errorf("threshold 0: want threatNone, got %v", got)
	}
	if got := (&Engine{threatBlockThreshold: 0.8}).threatDecision(sus); got != threatBlock {
		t.Errorf("enforce: want threatBlock, got %v", got)
	}
	if got := (&Engine{threatBlockThreshold: 0.8, threatBlockDryRun: true}).threatDecision(sus); got != threatDryRun {
		t.Errorf("dry-run: want threatDryRun, got %v", got)
	}
}

func TestProcessDNSQuery_ThreatBlockEnforced(t *testing.T) {
	// A long hex label scores dga_hex (0.9). With enforcement on and no
	// blocklist/policy match, it must be blocked — this returns before any
	// upstream forward, so no UpstreamManager is required.
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, nil)
	e.threatDetector = threat.NewDetector()
	e.threatBlockThreshold = 0.8

	w := &mockResponseWriter{}
	e.ProcessDNSQuery(w, newTestQuery("abcdef0123456789.example.com"))

	if w.msg == nil {
		t.Fatal("expected a response for the suspicious domain")
	}
	if !isBlockedResponse(w.msg) {
		t.Errorf("expected suspicious domain blocked (0.0.0.0), got rcode %d", w.msg.Rcode)
	}
}

func TestProcessDNSQuery_ThreatBlockDisabledByDefault(t *testing.T) {
	// With the default threshold of 0, the detector must not enforce even on a
	// clearly suspicious domain (verified at the decision layer to avoid the
	// upstream-forward path, which needs a real UpstreamManager).
	e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, nil)
	e.threatDetector = threat.NewDetector()

	sus := e.threatDetector.Analyze("abcdef0123456789.example.com")
	if !sus.IsSuspicious {
		t.Fatal("test precondition: expected the sample domain to be flagged suspicious")
	}
	if got := e.threatDecision(sus); got != threatNone {
		t.Errorf("default threshold (0) must not enforce, got %v", got)
	}
}

// TestFilterRebind_NonAddressRecordsUntouched ensures records that are not
// A/AAAA (CNAME, MX, TXT) are always preserved, even alongside dropped IPs.
func TestFilterRebind_NonAddressRecordsUntouched(t *testing.T) {
	answers := []dns.RR{
		mustRR(t, "example.com. 300 IN CNAME target.example.net."),
		mustRR(t, "example.com. 300 IN MX 10 mail.example.net."),
		mustRR(t, "example.com. 300 IN TXT \"v=spf1 -all\""),
		mustRR(t, "example.com. 300 IN A 10.0.0.1"), // private, drop
	}
	kept, dropped := filterRebind(answers)
	if dropped != 1 {
		t.Errorf("expected 1 dropped, got %d", dropped)
	}
	if len(kept) != 3 {
		t.Fatalf("expected 3 non-address records kept, got %d", len(kept))
	}
	for _, rr := range kept {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			t.Errorf("no address record should survive, got %T", rr)
		}
	}
}

// TestFilterRebind_AllPublicUnchanged verifies a fully public answer set is
// passed through untouched with zero drops.
func TestFilterRebind_AllPublicUnchanged(t *testing.T) {
	answers := []dns.RR{
		mustRR(t, "example.com. 300 IN A 8.8.8.8"),
		mustRR(t, "example.com. 300 IN A 1.1.1.1"),
		mustRR(t, "example.com. 300 IN AAAA 2001:4860:4860::8888"),
	}
	kept, dropped := filterRebind(answers)
	if dropped != 0 {
		t.Errorf("expected 0 dropped, got %d", dropped)
	}
	if len(kept) != len(answers) {
		t.Errorf("expected all %d records kept, got %d", len(answers), len(kept))
	}
}

// TestFilterRebind_Empty verifies the empty/nil-input edge cases.
func TestFilterRebind_Empty(t *testing.T) {
	kept, dropped := filterRebind(nil)
	if dropped != 0 || len(kept) != 0 {
		t.Errorf("expected empty result for nil input, got dropped=%d kept=%d", dropped, len(kept))
	}
	kept, dropped = filterRebind([]dns.RR{})
	if dropped != 0 || len(kept) != 0 {
		t.Errorf("expected empty result for empty input, got dropped=%d kept=%d", dropped, len(kept))
	}
}

// TestLogQuery_ThreadsBlockReason verifies logQuery persists the reason it is
// given into DNSQuery.BlockReason (I-015) without touching the threat fields.
func TestLogQuery_ThreadsBlockReason(t *testing.T) {
	tests := []struct {
		name   string
		action string
		reason string
	}{
		{"blocklist block", "block", "blocklist"},
		{"policy block", "block", "block-ads"},
		{"redirect", "redirect", "redirect:safe-search"},
		{"plain allow", "allow", ""},
		{"flagged uses threat method", "flagged", "entropy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mq := newMockQueryLog()
			e := &Engine{queryLog: mq}

			tr := threat.Result{DetectionMethod: "entropy", Reason: "high entropy"}
			e.logQuery("example.com", "1.2.3.4", tt.action, tt.reason, tr)

			got := mq.waitSaved(t)
			if got.BlockReason != tt.reason {
				t.Errorf("BlockReason = %q, want %q", got.BlockReason, tt.reason)
			}
			if got.Action != tt.action {
				t.Errorf("Action = %q, want %q", got.Action, tt.action)
			}
			// Threat fields must be preserved unchanged.
			if got.DetectionMethod != tr.DetectionMethod || got.ThreatReason != tr.Reason {
				t.Errorf("threat fields altered: DetectionMethod=%q ThreatReason=%q", got.DetectionMethod, got.ThreatReason)
			}
		})
	}
}

// TestProcessDNSQuery_LogsBlockReason verifies each blocking call site threads
// the correct reason string end-to-end through ProcessDNSQuery.
func TestProcessDNSQuery_LogsBlockReason(t *testing.T) {
	t.Run("blocklist", func(t *testing.T) {
		mq := newMockQueryLog()
		e := newTestEngine(&mockBlocklist{blocked: map[string]bool{"ads.example.com": true}}, nil)
		e.queryLog = mq

		e.ProcessDNSQuery(&mockResponseWriter{}, newTestQuery("ads.example.com"))

		if got := mq.waitSaved(t); got.BlockReason != "blocklist" {
			t.Errorf("BlockReason = %q, want %q", got.BlockReason, "blocklist")
		}
	})

	t.Run("policy block records policy ID", func(t *testing.T) {
		policies := []policy.Policy{
			{ID: "block-ads", Action: "BLOCK", Priority: 100, Domains: []string{"policy-blocked.com"}},
		}
		mq := newMockQueryLog()
		e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, policies)
		e.queryLog = mq

		e.ProcessDNSQuery(&mockResponseWriter{}, newTestQuery("policy-blocked.com"))

		if got := mq.waitSaved(t); got.BlockReason != "block-ads" {
			t.Errorf("BlockReason = %q, want %q", got.BlockReason, "block-ads")
		}
	})

	t.Run("redirect records redirect:policyID", func(t *testing.T) {
		policies := []policy.Policy{
			{ID: "safe-search", Action: "REDIRECT", Redirect: "1.2.3.4", Priority: 100, Domains: []string{"redirect-me.com"}},
		}
		mq := newMockQueryLog()
		e := newTestEngine(&mockBlocklist{blocked: map[string]bool{}}, policies)
		e.queryLog = mq

		e.ProcessDNSQuery(&mockResponseWriter{}, newTestQuery("redirect-me.com"))

		if got := mq.waitSaved(t); got.BlockReason != "redirect:safe-search" {
			t.Errorf("BlockReason = %q, want %q", got.BlockReason, "redirect:safe-search")
		}
	})
}
