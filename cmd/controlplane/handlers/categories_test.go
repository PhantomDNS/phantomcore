// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/internal/blocklist"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
	glog "gorm.io/gorm/logger"
)

// newCatalogTestHandler builds an APIHandler backed by an in-memory DB with the
// category/collection tables migrated. The returned feed servers must be closed by the
// caller.
func newCatalogTestHandler(t *testing.T) *APIHandler {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: glog.Default.LogMode(glog.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(
		&models.BlocklistSource{},
		&models.BlocklistSnapshot{},
		&models.BlocklistEntry{},
		&models.Category{},
		&models.Collection{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewAPIHandler(*repositories.NewStore(db), nil, nil, nil, nil, "")
}

func newCatalogRouter(h *APIHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	cat := r.Group("/api/v1/categories")
	cat.GET("", h.ListCategories)
	cat.GET("/:name", h.GetCategory)
	cat.PATCH("/:name", h.ToggleCategory)
	col := r.Group("/api/v1/collections")
	col.GET("", h.ListCollections)
	col.PATCH("/:name", h.ToggleCollection)
	return r
}

func decodeCategory(t *testing.T, w *httptest.ResponseRecorder) ResponseCategorySingle {
	t.Helper()
	var resp ResponseCategorySingle
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode category: %v (body=%s)", err, w.Body.String())
	}
	return resp
}

// installTwoFeedCategory replaces the handler's catalog with a single "testcat" category
// backed by two httptest feeds that overlap on one domain, so dedup can be asserted.
// Returns a close func for the servers.
func installTwoFeedCategory(t *testing.T, h *APIHandler) func() {
	t.Helper()
	feedA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 a.example.com\n0.0.0.0 shared.example.com\n"))
	}))
	feedB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 shared.example.com\n0.0.0.0 b.example.com\n"))
	}))
	h.Catalog = &blocklist.Catalog{
		Categories: []blocklist.CategoryDef{
			{
				Name:        "testcat",
				Description: "test category",
				Type:        blocklist.CategoryTypeSecurity,
				Feeds: []blocklist.Feed{
					{Name: "A", URL: feedA.URL, Format: "hosts"},
					{Name: "B", URL: feedB.URL, Format: "hosts"},
				},
			},
		},
		Collections: h.Catalog.Collections,
	}
	return func() {
		feedA.Close()
		feedB.Close()
	}
}

func TestListCategories_DefaultsOff(t *testing.T) {
	h := newCatalogTestHandler(t)
	// Use the built-in default catalog.
	r := newCatalogRouter(h)

	w := doRawJSON(t, r, http.MethodGet, "/api/v1/categories", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp ResponseCategoryList
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "success" {
		t.Errorf("expected success, got %q", resp.Status)
	}
	if len(resp.Data.List) == 0 {
		t.Fatal("expected built-in categories in list")
	}
	if resp.Data.EnabledCategories != 0 {
		t.Errorf("expected 0 enabled categories by default, got %d", resp.Data.EnabledCategories)
	}
	for _, cat := range resp.Data.List {
		if cat.Enabled {
			t.Errorf("category %q should be off by default", cat.Name)
		}
	}
}

func TestToggleCategory_EnablePullsFeedsAndDedups(t *testing.T) {
	h := newCatalogTestHandler(t)
	closeFeeds := installTwoFeedCategory(t, h)
	defer closeFeeds()
	r := newCatalogRouter(h)

	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/categories/testcat", `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enable expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	resp := decodeCategory(t, w)
	if !resp.Data.Enabled {
		t.Error("expected category enabled")
	}
	// Two feeds overlapping on one domain → 3 unique domains.
	if resp.Data.DomainsCount != 3 {
		t.Errorf("expected 3 deduped domains, got %d", resp.Data.DomainsCount)
	}
	if resp.Data.FeedsCount != 2 {
		t.Errorf("expected 2 feeds, got %d", resp.Data.FeedsCount)
	}

	// The dataplane checker must now block the aggregated domains.
	for _, d := range []string{"a.example.com", "shared.example.com", "b.example.com"} {
		if blocked, _ := h.Store.Blocklist.IsBlocked(d); !blocked {
			t.Errorf("expected %s blocked after enabling category", d)
		}
	}
}

func TestToggleCategory_TogglePersists(t *testing.T) {
	h := newCatalogTestHandler(t)
	closeFeeds := installTwoFeedCategory(t, h)
	defer closeFeeds()
	r := newCatalogRouter(h)

	// Enable.
	if w := doRawJSON(t, r, http.MethodPatch, "/api/v1/categories/testcat", `{"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("enable expected 200, got %d", w.Code)
	}

	// Persistence: a fresh GET reflects enabled + domain count.
	got := decodeCategory(t, doRawJSON(t, r, http.MethodGet, "/api/v1/categories/testcat", ""))
	if !got.Data.Enabled {
		t.Error("expected enabled=true to persist")
	}
	if got.Data.DomainsCount != 3 {
		t.Errorf("expected persisted count 3, got %d", got.Data.DomainsCount)
	}

	// Disable: entries dropped, state persists.
	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/categories/testcat", `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("disable expected 200, got %d", w.Code)
	}
	resp := decodeCategory(t, w)
	if resp.Data.Enabled {
		t.Error("expected enabled=false after disable")
	}
	if resp.Data.DomainsCount != 0 {
		t.Errorf("expected 0 domains after disable, got %d", resp.Data.DomainsCount)
	}
	if blocked, _ := h.Store.Blocklist.IsBlocked("a.example.com"); blocked {
		t.Error("expected a.example.com NOT blocked after disable")
	}
	got = decodeCategory(t, doRawJSON(t, r, http.MethodGet, "/api/v1/categories/testcat", ""))
	if got.Data.Enabled {
		t.Error("expected disabled state to persist")
	}
}

func TestToggleCategory_UnknownName(t *testing.T) {
	h := newCatalogTestHandler(t)
	r := newCatalogRouter(h)

	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/categories/does-not-exist", `{"enabled":true}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown category, got %d", w.Code)
	}
}
