package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
	glog "gorm.io/gorm/logger"
)

// hostsBody is a small hosts-format blocklist with three real domains (comments and
// non-blocking lines are ignored by the parser).
const hostsBody = `# test blocklist
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com
0.0.0.0 malware.example.net
1.2.3.4 ignored.example.com
`

// newTestHandler builds an APIHandler backed by a fresh in-memory sqlite DB.
// MaxOpenConns(1) keeps the background fetch goroutine and the handler on a single
// connection so they share the same in-memory database.
func newTestHandler(t *testing.T) *APIHandler {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: glog.Default.LogMode(glog.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(
		&models.BlocklistSource{},
		&models.BlocklistSnapshot{},
		&models.BlocklistEntry{},
	); err != nil {
		t.Fatalf("migrate failed: %v", err)
	}
	return NewAPIHandler(*repositories.NewStore(db), nil, nil, nil, nil, "")
}

func newTestRouter(h *APIHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/blocklists")
	g.GET("", h.ListBlocklists)
	g.POST("", h.CreateBlocklist)
	g.GET("/:id", h.GetBlocklist)
	g.PUT("/:id", h.UpdateBlocklist)
	g.PATCH("/:id", h.UpdateBlocklist)
	g.DELETE("/:id", h.DeleteBlocklist)
	return r
}

func newHostsServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(hostsBody))
	}))
}

func doRawJSON(t *testing.T, r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
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
	return w
}

func decodeSingle(t *testing.T, w *httptest.ResponseRecorder) ResponseBlocklistSingle {
	t.Helper()
	var resp ResponseBlocklistSingle
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode single response: %v (body=%s)", err, w.Body.String())
	}
	return resp
}

func TestListBlocklists_Empty(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)

	w := doRawJSON(t, r, http.MethodGet, "/api/v1/blocklists", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp ResponseBlocklistList
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "success" {
		t.Errorf("expected status success, got %q", resp.Status)
	}
	if resp.Data.TotalBlocklists != 0 {
		t.Errorf("expected 0 blocklists, got %d", resp.Data.TotalBlocklists)
	}
}

func TestCreateBlocklist_FetchesAndPersistsDomains(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)
	srv := newHostsServer()
	defer srv.Close()

	body := `{"id":"test","name":"Test List","url":"` + srv.URL + `","format":"hosts","category":"ads"}`
	w := doRawJSON(t, r, http.MethodPost, "/api/v1/blocklists", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}

	resp := decodeSingle(t, w)
	if resp.Status != "success" {
		t.Errorf("expected status success, got %q", resp.Status)
	}
	if resp.Error != nil {
		t.Errorf("expected nil error, got %v", *resp.Error)
	}
	// The real engine should have fetched/parsed the 3 blocking domains.
	if resp.Data.DomainsCount != 3 {
		t.Errorf("expected domains_count 3 after fetch, got %d", resp.Data.DomainsCount)
	}
	if !resp.Data.Enabled {
		t.Error("expected new blocklist to be enabled")
	}

	// Persistence: a fresh GET must reflect the stored source + count.
	wg := doRawJSON(t, r, http.MethodGet, "/api/v1/blocklists/test", "")
	if wg.Code != http.StatusOK {
		t.Fatalf("expected 200 on get, got %d", wg.Code)
	}
	got := decodeSingle(t, wg)
	if got.Data.DomainsCount != 3 {
		t.Errorf("expected persisted domains_count 3, got %d", got.Data.DomainsCount)
	}
	if got.Data.Name != "Test List" {
		t.Errorf("expected name 'Test List', got %q", got.Data.Name)
	}

	// The dataplane checker (live DB query) must now block the fetched domains.
	blocked, _ := h.Store.Blocklist.IsBlocked("ads.example.com")
	if !blocked {
		t.Error("expected ads.example.com to be blocked after create")
	}
}

func TestCreateBlocklist_RejectsNonHTTPURL(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)

	body := `{"id":"bad","name":"Bad","url":"ftp://evil.example","format":"hosts"}`
	w := doRawJSON(t, r, http.MethodPost, "/api/v1/blocklists", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-http url, got %d", w.Code)
	}
	resp := decodeSingle(t, w)
	if resp.Status != "error" || resp.Error == nil {
		t.Error("expected error envelope for bad url")
	}
}

func TestCreateBlocklist_RejectsDuplicate(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)
	srv := newHostsServer()
	defer srv.Close()

	body := `{"id":"dup","name":"Dup","url":"` + srv.URL + `","format":"hosts"}`
	if w := doRawJSON(t, r, http.MethodPost, "/api/v1/blocklists", body); w.Code != http.StatusCreated {
		t.Fatalf("first create expected 201, got %d", w.Code)
	}
	w := doRawJSON(t, r, http.MethodPost, "/api/v1/blocklists", body)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create expected 409, got %d", w.Code)
	}
}

func TestGetBlocklist_NotFound(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)

	w := doRawJSON(t, r, http.MethodGet, "/api/v1/blocklists/missing", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	resp := decodeSingle(t, w)
	if resp.Status != "error" || resp.Error == nil {
		t.Error("expected error envelope for missing blocklist")
	}
}

func TestUpdateBlocklist_InlineEdit(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)
	srv := newHostsServer()
	defer srv.Close()

	create := `{"id":"edit","name":"Old","url":"` + srv.URL + `","format":"hosts","category":"ads"}`
	if w := doRawJSON(t, r, http.MethodPost, "/api/v1/blocklists", create); w.Code != http.StatusCreated {
		t.Fatalf("create expected 201, got %d", w.Code)
	}

	// Rename + recategorize without touching the URL (no re-fetch).
	edit := `{"name":"New Name","category":"tracking"}`
	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/blocklists/edit", edit)
	if w.Code != http.StatusOK {
		t.Fatalf("update expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	resp := decodeSingle(t, w)
	if resp.Status != "success" {
		t.Errorf("expected success, got %q", resp.Status)
	}
	if resp.Data.Name != "New Name" || resp.Data.Category != "tracking" {
		t.Errorf("edit not applied: name=%q category=%q", resp.Data.Name, resp.Data.Category)
	}
	// Domains kept (URL unchanged).
	if resp.Data.DomainsCount != 3 {
		t.Errorf("expected domains preserved (3), got %d", resp.Data.DomainsCount)
	}

	// Persistence check.
	got := decodeSingle(t, doRawJSON(t, r, http.MethodGet, "/api/v1/blocklists/edit", ""))
	if got.Data.Name != "New Name" || got.Data.Category != "tracking" {
		t.Errorf("edit not persisted: name=%q category=%q", got.Data.Name, got.Data.Category)
	}
}

func TestUpdateBlocklist_ToggleDisableThenEnable(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)
	srv := newHostsServer()
	defer srv.Close()

	create := `{"id":"toggle","name":"Toggle","url":"` + srv.URL + `","format":"hosts"}`
	if w := doRawJSON(t, r, http.MethodPost, "/api/v1/blocklists", create); w.Code != http.StatusCreated {
		t.Fatalf("create expected 201, got %d", w.Code)
	}
	if blocked, _ := h.Store.Blocklist.IsBlocked("ads.example.com"); !blocked {
		t.Fatal("expected domain blocked after create")
	}

	// Disable: entries must be cleared so the dataplane stops blocking.
	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/blocklists/toggle", `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("disable expected 200, got %d", w.Code)
	}
	resp := decodeSingle(t, w)
	if resp.Data.Enabled {
		t.Error("expected enabled=false after disable")
	}
	if resp.Data.DomainsCount != 0 {
		t.Errorf("expected 0 domains after disable, got %d", resp.Data.DomainsCount)
	}
	if blocked, _ := h.Store.Blocklist.IsBlocked("ads.example.com"); blocked {
		t.Error("expected domain NOT blocked after disable")
	}

	// Re-enable: entries must be re-fetched.
	w = doRawJSON(t, r, http.MethodPatch, "/api/v1/blocklists/toggle", `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enable expected 200, got %d", w.Code)
	}
	resp = decodeSingle(t, w)
	if !resp.Data.Enabled {
		t.Error("expected enabled=true after re-enable")
	}
	if resp.Data.DomainsCount != 3 {
		t.Errorf("expected 3 domains re-fetched after enable, got %d", resp.Data.DomainsCount)
	}
	if blocked, _ := h.Store.Blocklist.IsBlocked("ads.example.com"); !blocked {
		t.Error("expected domain blocked again after re-enable")
	}
}

func TestUpdateBlocklist_NotFound(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)

	w := doRawJSON(t, r, http.MethodPut, "/api/v1/blocklists/nope", `{"name":"x"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDeleteBlocklist(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)
	srv := newHostsServer()
	defer srv.Close()

	create := `{"id":"del","name":"Del","url":"` + srv.URL + `","format":"hosts"}`
	if w := doRawJSON(t, r, http.MethodPost, "/api/v1/blocklists", create); w.Code != http.StatusCreated {
		t.Fatalf("create expected 201, got %d", w.Code)
	}

	w := doRawJSON(t, r, http.MethodDelete, "/api/v1/blocklists/del", "")
	if w.Code != http.StatusOK {
		t.Fatalf("delete expected 200, got %d", w.Code)
	}
	var resp ResponseGeneric
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "success" {
		t.Errorf("expected success, got %q", resp.Status)
	}

	// Gone + entries cascaded.
	if wg := doRawJSON(t, r, http.MethodGet, "/api/v1/blocklists/del", ""); wg.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", wg.Code)
	}
	if blocked, _ := h.Store.Blocklist.IsBlocked("ads.example.com"); blocked {
		t.Error("expected domain NOT blocked after delete")
	}
}

func TestDeleteBlocklist_NotFound(t *testing.T) {
	h := newTestHandler(t)
	r := newTestRouter(h)

	w := doRawJSON(t, r, http.MethodDelete, "/api/v1/blocklists/ghost", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}
