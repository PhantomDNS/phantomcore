package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com"); d.Action != policy.ActionDeny {
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
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com"); d.Action != policy.ActionAllow {
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
	if d, _ := h.PolicyEngine.Evaluate("ads.example.com"); d.Action != policy.ActionAllow {
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
	if d, _ := h.PolicyEngine.Evaluate("old.example.com"); d.Action != policy.ActionRedirect {
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
	if d, _ := h.PolicyEngine.Evaluate("new.example.com"); d.Action != policy.ActionRedirect {
		t.Fatalf("engine: expected Redirect for new.example.com, got %v", d.Action)
	}
	if d, _ := h.PolicyEngine.Evaluate("old.example.com"); d.Action != policy.ActionAllow {
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
