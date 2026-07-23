package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// setupPolicyTest builds a Gin router wired to a real APIHandler backed by a
// temp in-memory SQLite store and a real policy engine, mirroring the routes
// registered in cmd/controlplane/routes/router.go.
func setupPolicyTest(t *testing.T) (*gin.Engine, *APIHandler) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(&models.Policy{}); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	h := &APIHandler{
		Store:        *repositories.NewStore(db),
		PolicyEngine: policy.NewPolicyEngine(),
	}

	r := gin.New()
	g := r.Group("/api/v1/policies")
	g.GET("", h.ListPolicies)
	g.POST("", h.CreatePolicy)
	g.GET("/:id", h.GetPolicy)
	g.PUT("/:id", h.UpdatePolicy)
	g.PATCH("/:id", h.UpdatePolicy)
	g.DELETE("/:id", h.DeletePolicy)
	return r, h
}

func doReq(t *testing.T, r *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestPolicyCRUDLifecycle walks create -> list -> get -> update -> delete,
// asserting both storage persistence and that the running policy engine
// reflects every change.
func TestPolicyCRUDLifecycle(t *testing.T) {
	r, h := setupPolicyTest(t)

	// --- Create ---
	create := CreatePolicyRequest{
		ID:       "block-ads",
		Name:     "Block Ads",
		Action:   "BLOCK",
		Domains:  []string{"ads.example.com"},
		Priority: 100,
	}
	w := doReq(t, r, http.MethodPost, "/api/v1/policies", create)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	var created ResponsePolicySingle
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.Status != "success" || created.Data.ID != "block-ads" {
		t.Fatalf("unexpected create envelope: %+v", created)
	}

	// Persisted?
	stored, err := h.Store.Policies.GetByID("block-ads")
	if err != nil {
		t.Fatalf("expected policy persisted: %v", err)
	}
	if stored.Action != "BLOCK" {
		t.Fatalf("expected stored action BLOCK, got %s", stored.Action)
	}

	// Engine reflects the new BLOCK rule?
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com", ""); d.Action != policy.ActionDeny {
		t.Fatalf("engine: expected Deny for ads.example.com, got %v", d.Action)
	}

	// --- List ---
	w = doReq(t, r, http.MethodGet, "/api/v1/policies", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	var list ResponsePolicyList
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Data.TotalPolicies != 1 || list.Data.ActivePolicies != 1 {
		t.Fatalf("unexpected list counts: %+v", list.Data)
	}

	// --- Get ---
	w = doReq(t, r, http.MethodGet, "/api/v1/policies/block-ads", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", w.Code)
	}

	// --- Update (PUT): flip action BLOCK -> ALLOW ---
	newAction := "ALLOW"
	w = doReq(t, r, http.MethodPut, "/api/v1/policies/block-ads", map[string]interface{}{
		"action": newAction,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	stored, _ = h.Store.Policies.GetByID("block-ads")
	if stored.Action != "ALLOW" {
		t.Fatalf("expected stored action ALLOW after update, got %s", stored.Action)
	}
	// Engine now allows the same domain.
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com", ""); d.Action != policy.ActionAllow {
		t.Fatalf("engine: expected Allow after update, got %v", d.Action)
	}

	// --- Delete ---
	w = doReq(t, r, http.MethodDelete, "/api/v1/policies/block-ads", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", w.Code)
	}
	if _, err := h.Store.Policies.GetByID("block-ads"); err == nil {
		t.Fatal("expected policy gone after delete")
	}
	// Engine reflects removal (default Allow).
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com", ""); d.Action != policy.ActionAllow {
		t.Fatalf("engine: expected Allow after delete, got %v", d.Action)
	}
}

// TestPolicyPatchPartialAndRegexes verifies PATCH only touches provided fields,
// that regexes round-trip through storage, and that a domain change is applied
// to the engine.
func TestPolicyPatchPartialAndRegexes(t *testing.T) {
	r, h := setupPolicyTest(t)

	create := CreatePolicyRequest{
		ID:         "redir",
		Name:       "Redirect Test",
		Action:     "REDIRECT",
		RedirectIP: "10.0.0.1",
		Domains:    []string{"old.example.com"},
		Regexes:    []string{`.*\.tracker\.com$`},
		Priority:   50,
	}
	w := doReq(t, r, http.MethodPost, "/api/v1/policies", create)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}

	// Regexes persisted and returned.
	var created ResponsePolicySingle
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if len(created.Data.Regexes) != 1 || created.Data.Regexes[0] != `.*\.tracker\.com$` {
		t.Fatalf("regexes not returned: %+v", created.Data.Regexes)
	}

	// Engine blocks/redirects the initial domain.
	if d, _ := h.PolicyEngine.Evaluate("old.example.com", ""); d.Action != policy.ActionRedirect {
		t.Fatalf("engine: expected Redirect for old.example.com, got %v", d.Action)
	}

	// PATCH only the domains — name/action/priority must stay intact.
	w = doReq(t, r, http.MethodPatch, "/api/v1/policies/redir", map[string]interface{}{
		"domains": []string{"new.example.com"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	stored, _ := h.Store.Policies.GetByID("redir")
	if stored.Name != "Redirect Test" || stored.Action != "REDIRECT" || stored.Priority != 50 {
		t.Fatalf("patch clobbered untouched fields: %+v", stored)
	}

	// Engine now matches the new domain, not the old one.
	if d, _ := h.PolicyEngine.Evaluate("new.example.com", ""); d.Action != policy.ActionRedirect {
		t.Fatalf("engine: expected Redirect for new.example.com, got %v", d.Action)
	}
	if d, _ := h.PolicyEngine.Evaluate("old.example.com", ""); d.Action != policy.ActionAllow {
		t.Fatalf("engine: expected Allow for old.example.com after domain change, got %v", d.Action)
	}
}

func TestPolicyGetNotFound(t *testing.T) {
	r, _ := setupPolicyTest(t)
	w := doReq(t, r, http.MethodGet, "/api/v1/policies/nope", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPolicyUpdateNotFound(t *testing.T) {
	r, _ := setupPolicyTest(t)
	w := doReq(t, r, http.MethodPatch, "/api/v1/policies/nope", map[string]interface{}{"priority": 5})
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPolicyDeleteNotFound(t *testing.T) {
	r, _ := setupPolicyTest(t)
	w := doReq(t, r, http.MethodDelete, "/api/v1/policies/nope", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPolicyCreateInvalidAction(t *testing.T) {
	r, _ := setupPolicyTest(t)
	w := doReq(t, r, http.MethodPost, "/api/v1/policies", CreatePolicyRequest{
		ID:      "bad",
		Name:    "Bad",
		Action:  "NUKE",
		Domains: []string{"x.com"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid action, got %d", w.Code)
	}
}

func TestPolicyUpdateInvalidAction(t *testing.T) {
	r, h := setupPolicyTest(t)
	doReq(t, r, http.MethodPost, "/api/v1/policies", CreatePolicyRequest{
		ID: "ok", Name: "OK", Action: "BLOCK", Domains: []string{"x.com"},
	})
	w := doReq(t, r, http.MethodPatch, "/api/v1/policies/ok", map[string]interface{}{"action": "NUKE"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid action on update, got %d", w.Code)
	}
	// Rejected update must not have mutated storage.
	stored, err := h.Store.Policies.GetByID("ok")
	if err != nil {
		t.Fatalf("expected policy still present: %v", err)
	}
	if stored.Action != "BLOCK" {
		t.Fatalf("expected action unchanged (BLOCK), got %s", stored.Action)
	}
}

// setupPolicyTestWithClock mirrors setupPolicyTest but pins the engine to a
// fixed instant so scheduled-policy behaviour is deterministic (I-038).
func setupPolicyTestWithClock(t *testing.T, now time.Time) (*gin.Engine, *APIHandler) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(&models.Policy{}); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	h := &APIHandler{
		Store:        *repositories.NewStore(db),
		PolicyEngine: policy.NewPolicyEngineWithClock(func() time.Time { return now }),
	}

	r := gin.New()
	g := r.Group("/api/v1/policies")
	g.GET("", h.ListPolicies)
	g.POST("", h.CreatePolicy)
	g.GET("/:id", h.GetPolicy)
	g.PUT("/:id", h.UpdatePolicy)
	g.PATCH("/:id", h.UpdatePolicy)
	g.DELETE("/:id", h.DeletePolicy)
	return r, h
}

// TestPolicyScheduleRoundTrip verifies schedule fields persist and are returned
// by the API unchanged.
func TestPolicyScheduleRoundTrip(t *testing.T) {
	r, h := setupPolicyTest(t)

	create := CreatePolicyRequest{
		ID:           "sched",
		Name:         "Work Hours Block",
		Action:       "BLOCK",
		Domains:      []string{"social.example.com"},
		Priority:     100,
		ScheduleDays: []string{"mon", "tue", "wed", "thu", "fri"},
		StartTime:    "09:00",
		EndTime:      "17:00",
		Timezone:     "Asia/Kolkata",
	}
	w := doReq(t, r, http.MethodPost, "/api/v1/policies", create)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}

	// Persisted with the schedule columns populated.
	stored, err := h.Store.Policies.GetByID("sched")
	if err != nil {
		t.Fatalf("expected policy persisted: %v", err)
	}
	if stored.ScheduleStart != "09:00" || stored.ScheduleEnd != "17:00" || stored.Timezone != "Asia/Kolkata" {
		t.Fatalf("schedule not persisted: %+v", stored)
	}

	// GET returns the schedule fields.
	w = doReq(t, r, http.MethodGet, "/api/v1/policies/sched", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", w.Code)
	}
	var got ResponsePolicySingle
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.Data.StartTime != "09:00" || got.Data.EndTime != "17:00" || got.Data.Timezone != "Asia/Kolkata" {
		t.Fatalf("schedule not returned: %+v", got.Data)
	}
	if len(got.Data.ScheduleDays) != 5 {
		t.Fatalf("expected 5 schedule days, got %+v", got.Data.ScheduleDays)
	}
}

// TestPolicyScheduleEngineActive proves the running engine honours the schedule
// end to end: the same policy blocks inside its window and allows outside it.
func TestPolicyScheduleEngineActive(t *testing.T) {
	ist, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Fatalf("load tz: %v", err)
	}
	create := CreatePolicyRequest{
		ID:        "sched",
		Name:      "Work Hours Block",
		Action:    "BLOCK",
		Domains:   []string{"social.example.com"},
		Priority:  100,
		StartTime: "09:00",
		EndTime:   "17:00",
		Timezone:  "Asia/Kolkata",
	}

	// Inside window (12:00 IST) -> engine blocks.
	rIn, hIn := setupPolicyTestWithClock(t, time.Date(2026, 7, 20, 12, 0, 0, 0, ist))
	if w := doReq(t, rIn, http.MethodPost, "/api/v1/policies", create); w.Code != http.StatusCreated {
		t.Fatalf("create in-window: got %d body=%s", w.Code, w.Body.String())
	}
	if d, _ := hIn.PolicyEngine.Evaluate("social.example.com", ""); d.Action != policy.ActionDeny {
		t.Fatalf("engine: expected Deny inside window, got %v", d.Action)
	}

	// Outside window (20:00 IST) -> engine allows.
	rOut, hOut := setupPolicyTestWithClock(t, time.Date(2026, 7, 20, 20, 0, 0, 0, ist))
	if w := doReq(t, rOut, http.MethodPost, "/api/v1/policies", create); w.Code != http.StatusCreated {
		t.Fatalf("create out-window: got %d body=%s", w.Code, w.Body.String())
	}
	if d, _ := hOut.PolicyEngine.Evaluate("social.example.com", ""); d.Action != policy.ActionAllow {
		t.Fatalf("engine: expected Allow outside window, got %v", d.Action)
	}
}

func TestPolicyCreateInvalidSchedule(t *testing.T) {
	r, _ := setupPolicyTest(t)
	w := doReq(t, r, http.MethodPost, "/api/v1/policies", CreatePolicyRequest{
		ID:        "badtz",
		Name:      "Bad TZ",
		Action:    "BLOCK",
		Domains:   []string{"x.com"},
		StartTime: "09:00",
		EndTime:   "17:00",
		Timezone:  "Mars/Phobos",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid timezone, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestPolicyClientScopeCreateAndEngine verifies client_cidrs round-trips
// through the API (create -> get) and that the running engine applies the
// scoped policy per-client: an in-scope client is blocked, an out-of-scope
// client is allowed (I-014).
func TestPolicyClientScopeCreateAndEngine(t *testing.T) {
	r, h := setupPolicyTest(t)

	w := doReq(t, r, http.MethodPost, "/api/v1/policies", CreatePolicyRequest{
		ID:          "kids-social",
		Name:        "Block social for kids subnet",
		Action:      "BLOCK",
		Domains:     []string{"social.example.com"},
		ClientCIDRs: []string{"192.168.10.0/24"},
		Priority:    100,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}

	// client_cidrs round-trips through create response.
	var created ResponsePolicySingle
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if len(created.Data.ClientCIDRs) != 1 || created.Data.ClientCIDRs[0] != "192.168.10.0/24" {
		t.Fatalf("client_cidrs not returned: %+v", created.Data.ClientCIDRs)
	}

	// ...and through GET (i.e. persisted).
	w = doReq(t, r, http.MethodGet, "/api/v1/policies/kids-social", nil)
	var got ResponsePolicySingle
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got.Data.ClientCIDRs) != 1 || got.Data.ClientCIDRs[0] != "192.168.10.0/24" {
		t.Fatalf("client_cidrs not persisted: %+v", got.Data.ClientCIDRs)
	}

	// Engine applies the scope per-client.
	if d, _ := h.PolicyEngine.Evaluate("social.example.com", "192.168.10.5:53"); d.Action != policy.ActionDeny {
		t.Fatalf("engine: expected Deny for in-scope client, got %v", d.Action)
	}
	if d, _ := h.PolicyEngine.Evaluate("social.example.com", "192.168.20.5:53"); d.Action != policy.ActionAllow {
		t.Fatalf("engine: expected Allow for out-of-scope client, got %v", d.Action)
	}
}

// TestPolicyClientScopeInvalid verifies an unparseable client scope is rejected
// on create and never persisted.
func TestPolicyClientScopeInvalid(t *testing.T) {
	r, h := setupPolicyTest(t)
	w := doReq(t, r, http.MethodPost, "/api/v1/policies", CreatePolicyRequest{
		ID:          "bad-scope",
		Name:        "Bad scope",
		Action:      "BLOCK",
		Domains:     []string{"x.com"},
		ClientCIDRs: []string{"999.999.0.0/24"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid client scope, got %d body=%s", w.Code, w.Body.String())
	}
	if _, err := h.Store.Policies.GetByID("bad-scope"); err == nil {
		t.Fatal("expected policy with invalid scope not to be persisted")
	}
}

// TestPolicyClientScopePatchClears verifies PATCHing client_cidrs to an empty
// list clears the scope so the policy becomes unscoped (applies to all).
func TestPolicyClientScopePatchClears(t *testing.T) {
	r, h := setupPolicyTest(t)
	doReq(t, r, http.MethodPost, "/api/v1/policies", CreatePolicyRequest{
		ID: "scoped", Name: "Scoped", Action: "BLOCK",
		Domains: []string{"ads.example.com"}, ClientCIDRs: []string{"192.168.1.0/24"}, Priority: 100,
	})
	// Out-of-scope client initially allowed.
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com", "10.0.0.1:53"); d.Action != policy.ActionAllow {
		t.Fatalf("pre-clear: expected Allow for out-of-scope client, got %v", d.Action)
	}

	w := doReq(t, r, http.MethodPatch, "/api/v1/policies/scoped", map[string]interface{}{
		"client_cidrs": []string{},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	// Now unscoped: the same client is blocked.
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com", "10.0.0.1:53"); d.Action != policy.ActionDeny {
		t.Fatalf("post-clear: expected Deny for all clients, got %v", d.Action)
	}
}
