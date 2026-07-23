package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// envelope mirrors the standard control-plane response envelope.
type envelope struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
	Error  *string         `json:"error"`
}

func newTestResolverHandler(t *testing.T) (*gin.Engine, *APIHandler) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(&models.Resolver{}); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	// DataPlaneClient is nil: handlers persist-only, apply is a no-op (documented).
	store := repositories.Store{Resolvers: repositories.NewResolverRepo(db)}
	h := NewAPIHandler(store, nil, nil, nil)

	r := gin.New()
	dns := r.Group("/api/v1/dns")
	dns.GET("/resolvers", h.ListResolvers)
	dns.POST("/resolvers", h.CreateResolver)
	dns.PUT("/resolvers/:id", h.UpdateResolver)
	dns.PATCH("/resolvers/:id", h.UpdateResolver)
	dns.DELETE("/resolvers/:id", h.DeleteResolver)
	return r, h
}

func doJSON(t *testing.T, r *gin.Engine, method, path, body string) (*httptest.ResponseRecorder, envelope) {
	t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var env envelope
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatalf("%s %s: response is not valid JSON: %v (body=%s)", method, path, err, w.Body.String())
		}
	}
	return w, env
}

// createResolver is a helper that POSTs a resolver and returns its decoded form.
func createResolver(t *testing.T, r *gin.Engine, name, address, protocol string) Resolver {
	t.Helper()
	body := `{"name":"` + name + `","address":"` + address + `","protocol":"` + protocol + `"}`
	w, env := doJSON(t, r, http.MethodPost, "/api/v1/dns/resolvers", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %s: expected 201, got %d (body=%s)", address, w.Code, w.Body.String())
	}
	var res Resolver
	if err := json.Unmarshal(env.Data, &res); err != nil {
		t.Fatalf("create %s: failed to decode data: %v", address, err)
	}
	return res
}

func TestListResolvers_Empty(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	w, env := doJSON(t, r, http.MethodGet, "/api/v1/dns/resolvers", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if env.Status != "success" {
		t.Errorf("expected status success, got %q", env.Status)
	}
	if env.Error != nil {
		t.Errorf("expected nil error on success, got %v", *env.Error)
	}
	var list []Resolver
	if err := json.Unmarshal(env.Data, &list); err != nil {
		t.Fatalf("data is not a resolver list: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func TestCreateResolver_Success(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	res := createResolver(t, r, "Google", "8.8.8.8:53", "udp")
	if res.ID == "" {
		t.Error("expected generated ID")
	}
	if res.Address != "8.8.8.8:53" {
		t.Errorf("expected address 8.8.8.8:53, got %q", res.Address)
	}
	if res.Protocol != "udp" {
		t.Errorf("expected protocol udp, got %q", res.Protocol)
	}

	// Verify it is persisted and returned by List.
	w, env := doJSON(t, r, http.MethodGet, "/api/v1/dns/resolvers", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var list []Resolver
	json.Unmarshal(env.Data, &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 persisted resolver, got %d", len(list))
	}
	if list[0].ID != res.ID {
		t.Errorf("persisted ID mismatch: %q vs %q", list[0].ID, res.ID)
	}
}

func TestCreateResolver_DefaultsNameAndProtocol(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	// No name, no protocol -> name defaults to address, protocol defaults to udp.
	w, env := doJSON(t, r, http.MethodPost, "/api/v1/dns/resolvers", `{"address":"1.1.1.1:53"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var res Resolver
	json.Unmarshal(env.Data, &res)
	if res.Name != "1.1.1.1:53" {
		t.Errorf("expected name to default to address, got %q", res.Name)
	}
	if res.Protocol != "udp" {
		t.Errorf("expected protocol to default to udp, got %q", res.Protocol)
	}
}

func TestCreateResolver_MissingAddress(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	w, env := doJSON(t, r, http.MethodPost, "/api/v1/dns/resolvers", `{"name":"no-address"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing address, got %d", w.Code)
	}
	if env.Status != "error" {
		t.Errorf("expected status error, got %q", env.Status)
	}
	if env.Error == nil {
		t.Error("expected non-nil error message")
	}
}

func TestCreateResolver_InvalidAddress(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	cases := []string{
		`{"address":"8.8.8.8"}`,       // no port
		`{"address":"8.8.8.8:0"}`,     // port out of range
		`{"address":"8.8.8.8:70000"}`, // port out of range
		`{"address":":53"}`,           // empty host
		`{"address":"8.8.8.8:abc"}`,   // non-numeric port
	}
	for _, body := range cases {
		w, env := doJSON(t, r, http.MethodPost, "/api/v1/dns/resolvers", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: expected 400, got %d", body, w.Code)
		}
		if env.Status != "error" || env.Error == nil {
			t.Errorf("body %s: expected error envelope", body)
		}
	}

	// Nothing should have been persisted.
	_, env := doJSON(t, r, http.MethodGet, "/api/v1/dns/resolvers", "")
	var list []Resolver
	json.Unmarshal(env.Data, &list)
	if len(list) != 0 {
		t.Errorf("expected no resolvers persisted after invalid creates, got %d", len(list))
	}
}

func TestCreateResolver_InvalidProtocol(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	w, env := doJSON(t, r, http.MethodPost, "/api/v1/dns/resolvers", `{"address":"8.8.8.8:53","protocol":"https"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid protocol, got %d", w.Code)
	}
	if env.Status != "error" || env.Error == nil {
		t.Error("expected error envelope for invalid protocol")
	}
}

func TestCreateResolver_AppendsPosition(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	first := createResolver(t, r, "a", "8.8.8.8:53", "udp")
	second := createResolver(t, r, "b", "1.1.1.1:53", "udp")
	if second.Position <= first.Position {
		t.Errorf("expected second resolver position (%d) > first (%d)", second.Position, first.Position)
	}
}

func TestUpdateResolver_EditAddress(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	res := createResolver(t, r, "Google", "8.8.8.8:53", "udp")

	w, env := doJSON(t, r, http.MethodPut, "/api/v1/dns/resolvers/"+res.ID, `{"address":"9.9.9.9:53","protocol":"tcp"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var updated Resolver
	json.Unmarshal(env.Data, &updated)
	if updated.Address != "9.9.9.9:53" {
		t.Errorf("expected updated address 9.9.9.9:53, got %q", updated.Address)
	}
	if updated.Protocol != "tcp" {
		t.Errorf("expected updated protocol tcp, got %q", updated.Protocol)
	}
}

func TestUpdateResolver_InvalidAddress(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	res := createResolver(t, r, "Google", "8.8.8.8:53", "udp")

	w, env := doJSON(t, r, http.MethodPatch, "/api/v1/dns/resolvers/"+res.ID, `{"address":"not-valid"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid address update, got %d", w.Code)
	}
	if env.Status != "error" || env.Error == nil {
		t.Error("expected error envelope")
	}
}

func TestUpdateResolver_NotFound(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	w, env := doJSON(t, r, http.MethodPut, "/api/v1/dns/resolvers/does-not-exist", `{"name":"x"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if env.Status != "error" || env.Error == nil {
		t.Error("expected error envelope for not found")
	}
}

func TestUpdateResolver_Reorder(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	first := createResolver(t, r, "a", "8.8.8.8:53", "udp")
	second := createResolver(t, r, "b", "1.1.1.1:53", "udp")

	// Move the second resolver ahead of the first by lowering its position.
	newPos := first.Position - 1
	body := `{"position":` + strconv.Itoa(newPos) + `}`
	w, _ := doJSON(t, r, http.MethodPatch, "/api/v1/dns/resolvers/"+second.ID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on reorder, got %d", w.Code)
	}

	// List must now return the second resolver first (ordered by position asc).
	_, env := doJSON(t, r, http.MethodGet, "/api/v1/dns/resolvers", "")
	var list []Resolver
	json.Unmarshal(env.Data, &list)
	if len(list) != 2 {
		t.Fatalf("expected 2 resolvers, got %d", len(list))
	}
	if list[0].ID != second.ID {
		t.Errorf("expected reordered resolver first, got %q", list[0].ID)
	}
}

func TestDeleteResolver(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	res := createResolver(t, r, "Google", "8.8.8.8:53", "udp")

	w, env := doJSON(t, r, http.MethodDelete, "/api/v1/dns/resolvers/"+res.ID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d", w.Code)
	}
	if env.Status != "success" {
		t.Errorf("expected success, got %q", env.Status)
	}

	// List is empty afterwards.
	_, listEnv := doJSON(t, r, http.MethodGet, "/api/v1/dns/resolvers", "")
	var list []Resolver
	json.Unmarshal(listEnv.Data, &list)
	if len(list) != 0 {
		t.Errorf("expected 0 resolvers after delete, got %d", len(list))
	}
}

func TestDeleteResolver_NotFound(t *testing.T) {
	r, _ := newTestResolverHandler(t)

	w, env := doJSON(t, r, http.MethodDelete, "/api/v1/dns/resolvers/nope", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if env.Status != "error" || env.Error == nil {
		t.Error("expected error envelope for not found")
	}
}

func TestValidateResolverAddress(t *testing.T) {
	valid := []string{"8.8.8.8:53", "1.1.1.1:853", "[2606:4700:4700::1111]:53", "dns.example.com:53"}
	for _, a := range valid {
		if err := validateResolverAddress(a); err != nil {
			t.Errorf("expected %q valid, got error: %v", a, err)
		}
	}
	invalid := []string{"8.8.8.8", "8.8.8.8:0", "8.8.8.8:70000", ":53", "8.8.8.8:abc", ""}
	for _, a := range invalid {
		if err := validateResolverAddress(a); err == nil {
			t.Errorf("expected %q invalid, got nil error", a)
		}
	}
}

func TestNormalizeProtocol(t *testing.T) {
	cases := map[string]struct {
		want string
		err  bool
	}{
		"":     {"udp", false},
		"udp":  {"udp", false},
		"TCP":  {"tcp", false},
		"Udp":  {"udp", false},
		"quic": {"", true},
	}
	for in, exp := range cases {
		got, err := normalizeProtocol(in)
		if exp.err {
			if err == nil {
				t.Errorf("normalizeProtocol(%q): expected error", in)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeProtocol(%q): unexpected error %v", in, err)
		}
		if got != exp.want {
			t.Errorf("normalizeProtocol(%q) = %q, want %q", in, got, exp.want)
		}
	}
}
