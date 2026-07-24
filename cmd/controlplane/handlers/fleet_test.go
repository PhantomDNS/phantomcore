package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/cmd/controlplane/handlers"
	"github.com/lopster568/phantomDNS/cmd/controlplane/middlewares"
	"github.com/lopster568/phantomDNS/cmd/controlplane/routes"
	"github.com/lopster568/phantomDNS/internal/fleet"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	testAdminToken = "admin-token-123"
	testBoxToken   = "box-token-abc"
)

// newFleetTestServer wires the real router and global auth middleware over an
// in-memory DB, exactly as main.go does, so the tests exercise real auth flow.
func newFleetTestServer(t *testing.T) (*gin.Engine, *fleet.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&models.AdminCredential{}, &models.Statistics{}, &models.DNSQuery{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	repos := repositories.NewStore(db)
	// Complete setup so the global auth middleware is active (not in setup mode).
	if err := repos.Auth.CreateAdmin("hash", testAdminToken); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	store := fleet.NewStore(90*time.Second, nil)
	h := handlers.NewAPIHandler(*repos, nil, nil, nil, store, testBoxToken)

	r := gin.New()
	r.Use(middlewares.Auth(repos.Auth))
	routes.RegisterRoutes(r, h)
	return r, store
}

func do(r *gin.Engine, method, path, token string, body []byte) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestFleetHeartbeat_IngestsAndConsolidates(t *testing.T) {
	r, _ := newFleetTestServer(t)

	// Box posts a heartbeat using the dedicated box token.
	body, _ := json.Marshal(fleet.Heartbeat{SiteID: "box-1", Name: "Clinic A", QPS: 15, BlockedPercent: 9})
	w := do(r, http.MethodPost, "/api/v1/fleet/heartbeat", testBoxToken, body)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: status = %d body=%s", w.Code, w.Body.String())
	}

	// Admin pulls the consolidated view.
	w = do(r, http.MethodGet, "/api/v1/fleet", testAdminToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get fleet: status = %d body=%s", w.Code, w.Body.String())
	}

	var resp handlers.ResponseFleet
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Total != 1 || len(resp.Data.Sites) != 1 {
		t.Fatalf("expected 1 site, got %+v", resp.Data)
	}
	site := resp.Data.Sites[0]
	if site.SiteID != "box-1" || site.Name != "Clinic A" || site.Status != fleet.StatusUp {
		t.Errorf("unexpected consolidated site: %+v", site)
	}
	if site.QPS != 15 || site.BlockedPercent != 9 {
		t.Errorf("metadata mismatch: %+v", site)
	}
}

func TestFleetHeartbeat_AuthRequired(t *testing.T) {
	r, store := newFleetTestServer(t)

	// Missing box token -> rejected, nothing ingested.
	body, _ := json.Marshal(fleet.Heartbeat{SiteID: "box-1"})
	w := do(r, http.MethodPost, "/api/v1/fleet/heartbeat", "", body)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}

	// Wrong box token -> rejected.
	w = do(r, http.MethodPost, "/api/v1/fleet/heartbeat", "wrong", body)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", w.Code)
	}

	// The admin key must NOT work as a box token on the heartbeat endpoint.
	w = do(r, http.MethodPost, "/api/v1/fleet/heartbeat", testAdminToken, body)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("admin token on heartbeat: status = %d, want 401", w.Code)
	}

	if got := store.Snapshot().Total; got != 0 {
		t.Errorf("expected no sites ingested on failed auth, got %d", got)
	}
}

func TestFleet_GetRequiresAdmin(t *testing.T) {
	r, _ := newFleetTestServer(t)

	// No token -> global admin auth rejects.
	w := do(r, http.MethodGet, "/api/v1/fleet", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}

	// Box token is not the admin key -> rejected.
	w = do(r, http.MethodGet, "/api/v1/fleet", testBoxToken, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("box token on admin view: status = %d, want 401", w.Code)
	}

	// Admin token -> allowed.
	w = do(r, http.MethodGet, "/api/v1/fleet", testAdminToken, nil)
	if w.Code != http.StatusOK {
		t.Errorf("admin token: status = %d, want 200", w.Code)
	}
}
