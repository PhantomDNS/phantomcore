// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
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
	gormlogger "gorm.io/gorm/logger"
)

func setupRollupHandler(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(&models.DNSQuery{}); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	h := &APIHandler{
		Store: repositories.Store{
			QueryLogs: repositories.NewGormQueryLogRepo(db),
		},
	}

	r := gin.New()
	r.GET("/api/v1/analytics/rollups", h.GetAnalyticsRollups)
	return r, db
}

func seedRollupRows(t *testing.T, db *gorm.DB) {
	t.Helper()
	ts := func(h, m int) time.Time { return time.Date(2024, 1, 1, h, m, 0, 0, time.UTC) }
	rows := []models.DNSQuery{
		{Domain: "ads.example.com", ClientIP: "10.0.0.1", Action: "block", Timestamp: ts(10, 0)},
		{Domain: "ads.example.com", ClientIP: "10.0.0.2", Action: "block", Timestamp: ts(10, 5)},
		{Domain: "good.org", ClientIP: "10.0.0.1", Action: "allow", Timestamp: ts(10, 10)},
		{Domain: "news.example.com", ClientIP: "10.0.0.1", Action: "allow", Timestamp: ts(11, 0)},
		{Domain: "phish.evil", ClientIP: "10.0.0.3", Action: "flagged", IsSuspicious: true, Timestamp: ts(11, 30)},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("failed to seed row %d: %v", i, err)
		}
	}
}

func doRollupGET(t *testing.T, r *gin.Engine, target string) (*httptest.ResponseRecorder, ResponseAnalyticsRollups) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var body ResponseAnalyticsRollups
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response: %v (body: %s)", err, w.Body.String())
		}
	}
	return w, body
}

func TestGetAnalyticsRollups_Shape(t *testing.T) {
	r, db := setupRollupHandler(t)
	seedRollupRows(t, db)

	w, body := doRollupGET(t, r, "/api/v1/analytics/rollups")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if body.Status != "success" || body.Error != nil {
		t.Fatalf("unexpected envelope: status=%q err=%v", body.Status, body.Error)
	}
	if body.Data.Window.TopN != repositories.DefaultAnalyticsTopN {
		t.Errorf("expected default top-N %d, got %d", repositories.DefaultAnalyticsTopN, body.Data.Window.TopN)
	}

	// Top clients: 10.0.0.1 busiest with 3 queries, 1 blocked.
	if len(body.Data.TopClients) != 3 {
		t.Fatalf("expected 3 clients, got %d", len(body.Data.TopClients))
	}
	if body.Data.TopClients[0].ClientIP != "10.0.0.1" || body.Data.TopClients[0].Total != 3 {
		t.Errorf("top client wrong: %+v", body.Data.TopClients[0])
	}
	if body.Data.TopClients[0].Blocked != 1 {
		t.Errorf("expected top client blocked=1, got %d", body.Data.TopClients[0].Blocked)
	}

	// Top blocked domains: ads.example.com blocked twice.
	if len(body.Data.TopBlocked) != 1 {
		t.Fatalf("expected 1 blocked domain, got %d (%+v)", len(body.Data.TopBlocked), body.Data.TopBlocked)
	}
	if body.Data.TopBlocked[0].Domain != "ads.example.com" || body.Data.TopBlocked[0].Count != 2 {
		t.Errorf("top blocked wrong: %+v", body.Data.TopBlocked[0])
	}

	// Categories: block=2, allow=2, flagged=1.
	catCounts := map[string]int64{}
	for _, c := range body.Data.Categories {
		catCounts[c.Category] = c.Count
	}
	if catCounts["block"] != 2 || catCounts["allow"] != 2 || catCounts["flagged"] != 1 {
		t.Errorf("category breakdown wrong: %+v", body.Data.Categories)
	}

	// Heatmap: hour 10 has block+allow, hour 11 has allow+flagged.
	if len(body.Data.Heatmap) == 0 {
		t.Errorf("expected non-empty heatmap")
	}

	// No client_ip -> empty timeline; no from/to -> no anomaly.
	if len(body.Data.Timeline) != 0 {
		t.Errorf("expected empty timeline without client_ip, got %d", len(body.Data.Timeline))
	}
	if body.Data.Anomaly != nil {
		t.Errorf("expected nil anomaly without a full window")
	}
}

func TestGetAnalyticsRollups_ClientTimeline(t *testing.T) {
	r, db := setupRollupHandler(t)
	seedRollupRows(t, db)

	_, body := doRollupGET(t, r, "/api/v1/analytics/rollups?client_ip=10.0.0.1")
	if body.Data.Window.ClientIP != "10.0.0.1" {
		t.Errorf("expected echoed client_ip, got %q", body.Data.Window.ClientIP)
	}
	// client 1 active in hour 10 (2 queries) and hour 11 (1 query).
	if len(body.Data.Timeline) != 2 {
		t.Fatalf("expected 2 timeline buckets, got %d (%+v)", len(body.Data.Timeline), body.Data.Timeline)
	}
	if body.Data.Timeline[0].Total != 2 || body.Data.Timeline[1].Total != 1 {
		t.Errorf("timeline totals wrong: %+v", body.Data.Timeline)
	}
}

func TestGetAnalyticsRollups_TopNClamped(t *testing.T) {
	r, db := setupRollupHandler(t)
	seedRollupRows(t, db)

	_, body := doRollupGET(t, r, "/api/v1/analytics/rollups?top=100000")
	if body.Data.Window.TopN != repositories.MaxAnalyticsTopN {
		t.Errorf("expected clamped top-N %d, got %d", repositories.MaxAnalyticsTopN, body.Data.Window.TopN)
	}

	// top=1 limits the leaderboard to the single busiest client.
	_, body = doRollupGET(t, r, "/api/v1/analytics/rollups?top=1")
	if len(body.Data.TopClients) != 1 {
		t.Errorf("expected 1 client with top=1, got %d", len(body.Data.TopClients))
	}
}

func TestGetAnalyticsRollups_WithWindowIncludesAnomaly(t *testing.T) {
	r, db := setupRollupHandler(t)
	seedRollupRows(t, db)

	// A full [from,to] window must produce an anomaly digest (compared against
	// the preceding equal-length window, which is empty here).
	from := "2024-01-01T10:00:00Z"
	to := "2024-01-01T11:59:00Z"
	_, body := doRollupGET(t, r, "/api/v1/analytics/rollups?from="+from+"&to="+to)
	if body.Data.Anomaly == nil {
		t.Fatal("expected anomaly digest for a full window")
	}
	if body.Data.Anomaly.TotalCurrent != 5 {
		t.Errorf("expected current total 5, got %d", body.Data.Anomaly.TotalCurrent)
	}
	if body.Data.Anomaly.TotalPrior != 0 {
		t.Errorf("expected prior total 0 (empty preceding window), got %d", body.Data.Anomaly.TotalPrior)
	}
}

func TestGetAnalyticsRollups_BadParams(t *testing.T) {
	r, db := setupRollupHandler(t)
	seedRollupRows(t, db)

	cases := []string{
		"?from=not-a-time",
		"?to=2024-13-40",
		"?top=abc",
		"?top=0",
		"?top=-5",
		"?from=2024-01-02T00:00:00Z&to=2024-01-01T00:00:00Z", // to before from
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/rollups"+q, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("query %q: expected 400, got %d (body: %s)", q, w.Code, w.Body.String())
			}
		})
	}
}
