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
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// configEnvelope is the standard response envelope with a typed Config payload.
type configEnvelope struct {
	Status string  `json:"status"`
	Data   Config  `json:"data"`
	Error  *string `json:"error"`
}

// summaryEnvelope is the standard response envelope with an import summary.
type summaryEnvelope struct {
	Status string        `json:"status"`
	Data   ImportSummary `json:"data"`
	Error  *string       `json:"error"`
}

func newConfigTestServer(t *testing.T) (*gin.Engine, *repositories.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.Policy{},
		&models.SystemState{},
		&models.BlocklistSource{},
		&models.BlocklistSnapshot{},
		&models.BlocklistEntry{},
	); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	store := repositories.NewStore(db)
	// DataPlaneClient and Inventory are nil: import persists and skips the
	// best-effort reload; handlers must treat a nil Inventory as empty.
	h := NewAPIHandler(*store, nil, nil, nil, nil, "")

	r := gin.New()
	api := r.Group("/api/v1")
	api.GET("/config/export", h.ExportConfig)
	api.POST("/config/import", h.ImportConfig)
	return r, store
}

// seedConfig loads a representative config directly into the repositories.
func seedConfig(t *testing.T, store *repositories.Store) {
	t.Helper()
	now := time.Now()

	if err := store.DB.Create(&models.SystemState{
		ID: 1, DNSEnabled: false, PolicyEnabled: true, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed system state: %v", err)
	}

	if err := store.Policies.Create(&models.Policy{
		ID: "block-ads", Name: "Block Ads", Description: "no ads",
		Category: "ads", Action: "BLOCK",
		Domains: `["ads.example.com","tracker.com"]`, Priority: 100, Enabled: true,
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := store.Policies.Create(&models.Policy{
		ID: "redirect-safe", Name: "Safe Search", Action: "REDIRECT",
		RedirectIP: "10.0.0.1", Domains: `["google.com"]`, Priority: 50, Enabled: true,
	}); err != nil {
		t.Fatalf("seed policy 2: %v", err)
	}

	if err := store.Blocklist.CreateSource(&models.BlocklistSource{
		ID: "steven-black", Name: "StevenBlack", URL: "https://example.com/hosts",
		Format: "hosts", Category: "ads", Priority: 10, Enabled: true, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed blocklist: %v", err)
	}
}

func doExport(t *testing.T, r *gin.Engine) configEnvelope {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/export", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var env configEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("export: failed to decode body: %v", err)
	}
	return env
}

func doImport(t *testing.T, r *gin.Engine, cfg Config, query string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal import body: %v", err)
	}
	url := "/api/v1/config/import"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestExportConfig_Shape(t *testing.T) {
	r, store := newConfigTestServer(t)
	seedConfig(t, store)

	env := doExport(t, r)

	if env.Status != "success" {
		t.Fatalf("expected status success, got %q", env.Status)
	}
	if env.Data.Version != ConfigVersion {
		t.Errorf("expected version %q, got %q", ConfigVersion, env.Data.Version)
	}
	if len(env.Data.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(env.Data.Policies))
	}
	// Deterministic id ordering.
	if env.Data.Policies[0].ID != "block-ads" || env.Data.Policies[1].ID != "redirect-safe" {
		t.Errorf("policies not id-sorted: %+v", env.Data.Policies)
	}
	p0 := env.Data.Policies[0]
	if p0.Action != "BLOCK" || p0.Priority != 100 || !p0.Enabled {
		t.Errorf("unexpected policy fields: %+v", p0)
	}
	if len(p0.Domains) != 2 || p0.Domains[0] != "ads.example.com" {
		t.Errorf("unexpected domains: %+v", p0.Domains)
	}
	if len(env.Data.Blocklists) != 1 {
		t.Fatalf("expected 1 blocklist, got %d", len(env.Data.Blocklists))
	}
	b0 := env.Data.Blocklists[0]
	if b0.ID != "steven-black" || b0.URL != "https://example.com/hosts" || b0.Format != "hosts" {
		t.Errorf("unexpected blocklist fields: %+v", b0)
	}
	if env.Data.Settings.DNSEnabled != false || env.Data.Settings.PolicyEnabled != true {
		t.Errorf("unexpected settings: %+v", env.Data.Settings)
	}
}

func TestImportExportRoundTrip(t *testing.T) {
	r, store := newConfigTestServer(t)
	seedConfig(t, store)

	first := doExport(t, r)

	// Re-import the exported config, then export again.
	w := doImport(t, r, first.Data, "")
	if w.Code != http.StatusOK {
		t.Fatalf("import: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var sum summaryEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &sum); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if sum.Data.DryRun {
		t.Error("expected dry_run=false on real import")
	}
	if sum.Data.PoliciesImported != 2 || sum.Data.BlocklistsImported != 1 {
		t.Errorf("unexpected summary counts: %+v", sum.Data)
	}

	second := doExport(t, r)

	firstJSON, _ := json.Marshal(first.Data)
	secondJSON, _ := json.Marshal(second.Data)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Errorf("round-trip not stable:\n first: %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestImportInvalidRejected(t *testing.T) {
	r, store := newConfigTestServer(t)
	seedConfig(t, store)

	before, err := store.Policies.List()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "unsupported version",
			cfg:  Config{Version: "99"},
		},
		{
			name: "invalid policy action",
			cfg: Config{Version: ConfigVersion, Policies: []ConfigPolicy{
				{ID: "new-pol", Name: "New", Action: "NUKE", Domains: []string{"x.com"}},
			}},
		},
		{
			name: "blocklist with non-http url",
			cfg: Config{Version: ConfigVersion, Blocklists: []ConfigBlocklist{
				{ID: "bad", Name: "Bad", URL: "file:///etc/passwd", Format: "hosts"},
			}},
		},
		{
			name: "policy missing id",
			cfg: Config{Version: ConfigVersion, Policies: []ConfigPolicy{
				{Name: "No ID", Action: "BLOCK"},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doImport(t, r, tc.cfg, "")
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d (body: %s)", w.Code, w.Body.String())
			}
		})
	}

	// Nothing should have been persisted by any rejected import.
	after, err := store.Policies.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("invalid import mutated state: before=%d after=%d", len(before), len(after))
	}
}

func TestImportDryRunDoesNotPersist(t *testing.T) {
	r, store := newConfigTestServer(t)
	// Start empty (only default settings created on first Get).

	cfg := Config{
		Version: ConfigVersion,
		Policies: []ConfigPolicy{
			{ID: "dry-pol", Name: "Dry", Action: "BLOCK", Domains: []string{"a.com"}, Enabled: true},
		},
		Blocklists: []ConfigBlocklist{
			{ID: "dry-bl", Name: "Dry BL", URL: "https://example.com/list", Format: "hosts", Enabled: true},
		},
		Settings: ConfigSettings{DNSEnabled: true, PolicyEnabled: true},
	}

	w := doImport(t, r, cfg, "dry_run=true")
	if w.Code != http.StatusOK {
		t.Fatalf("dry-run: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var sum summaryEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &sum); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if !sum.Data.DryRun {
		t.Error("expected dry_run=true in summary")
	}
	if sum.Data.PoliciesImported != 1 || sum.Data.BlocklistsImported != 1 {
		t.Errorf("dry-run summary should report would-import counts: %+v", sum.Data)
	}

	// Persistence must not have happened.
	pols, err := store.Policies.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 0 {
		t.Errorf("dry-run persisted %d policies, expected 0", len(pols))
	}
	srcs, err := store.Blocklist.ListSources()
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 0 {
		t.Errorf("dry-run persisted %d blocklist sources, expected 0", len(srcs))
	}
}
