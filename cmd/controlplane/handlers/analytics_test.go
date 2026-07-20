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

func setupLogTestHandler(t *testing.T) (*gin.Engine, *gorm.DB) {
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
	r.GET("/api/v1/analytics/logs", h.GetQueryLogs)
	return r, db
}

func seedHandlerLogs(t *testing.T, db *gorm.DB) {
	t.Helper()
	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	rows := []models.DNSQuery{
		{Domain: "ads.example.com", ClientIP: "10.0.0.1", Action: "block", IsSuspicious: false},
		{Domain: "good.org", ClientIP: "10.0.0.1", Action: "allow", IsSuspicious: false},
		{Domain: "malware.bad", ClientIP: "10.0.0.2", Action: "flagged", IsSuspicious: true},
		{Domain: "news.example.com", ClientIP: "10.0.0.1", Action: "allow", IsSuspicious: false},
		{Domain: "phish.evil", ClientIP: "10.0.0.3", Action: "flagged", IsSuspicious: true},
	}
	for i := range rows {
		rows[i].Timestamp = base.Add(time.Duration(i) * time.Minute)
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("failed to seed row %d: %v", i, err)
		}
	}
}

func doGET(t *testing.T, r *gin.Engine, target string) (*httptest.ResponseRecorder, ResponseQueryLogPage) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var body ResponseQueryLogPage
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response: %v (body: %s)", err, w.Body.String())
		}
	}
	return w, body
}

func TestGetQueryLogs_EnvelopeAndDefaults(t *testing.T) {
	r, db := setupLogTestHandler(t)
	seedHandlerLogs(t, db)

	w, body := doGET(t, r, "/api/v1/analytics/logs")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body.Status != "success" {
		t.Errorf("expected status success, got %q", body.Status)
	}
	if body.Error != nil {
		t.Errorf("expected nil error, got %v", *body.Error)
	}
	if body.Data.PageInfo.Total != 5 {
		t.Errorf("expected total 5, got %d", body.Data.PageInfo.Total)
	}
	if body.Data.PageInfo.Limit != repositories.DefaultQueryLogPageSize {
		t.Errorf("expected default limit %d, got %d", repositories.DefaultQueryLogPageSize, body.Data.PageInfo.Limit)
	}
	if len(body.Data.Items) != 5 {
		t.Errorf("expected 5 items, got %d", len(body.Data.Items))
	}
	if body.Data.PageInfo.HasMore {
		t.Errorf("expected has_more=false when all rows fit on one page")
	}
	// Newest first.
	if len(body.Data.Items) > 0 && body.Data.Items[0].Domain != "phish.evil" {
		t.Errorf("expected newest row first, got %q", body.Data.Items[0].Domain)
	}
}

func TestGetQueryLogs_PaginationHasMore(t *testing.T) {
	r, db := setupLogTestHandler(t)
	seedHandlerLogs(t, db)

	w, body := doGET(t, r, "/api/v1/analytics/logs?limit=2&offset=0")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(body.Data.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(body.Data.Items))
	}
	if body.Data.PageInfo.Total != 5 {
		t.Errorf("expected total 5, got %d", body.Data.PageInfo.Total)
	}
	if !body.Data.PageInfo.HasMore {
		t.Errorf("expected has_more=true on first of multiple pages")
	}

	// Last page should have has_more=false.
	_, last := doGET(t, r, "/api/v1/analytics/logs?limit=2&offset=4")
	if len(last.Data.Items) != 1 {
		t.Errorf("expected 1 item on last page, got %d", len(last.Data.Items))
	}
	if last.Data.PageInfo.HasMore {
		t.Errorf("expected has_more=false on last page")
	}
}

func TestGetQueryLogs_Filters(t *testing.T) {
	r, db := setupLogTestHandler(t)
	seedHandlerLogs(t, db)

	cases := []struct {
		name  string
		query string
		total int64
	}{
		{"client_ip", "?client_ip=10.0.0.1", 3},
		{"action", "?action=flagged", 2},
		{"domain_substring", "?domain=example.com", 2},
		{"suspicious", "?suspicious=true", 2},
		{"combined", "?client_ip=10.0.0.1&action=allow", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, body := doGET(t, r, "/api/v1/analytics/logs"+tc.query)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", w.Code)
			}
			if body.Data.PageInfo.Total != tc.total {
				t.Errorf("query %q: expected total %d, got %d", tc.query, tc.total, body.Data.PageInfo.Total)
			}
		})
	}
}

func TestGetQueryLogs_BadParams(t *testing.T) {
	r, db := setupLogTestHandler(t)
	seedHandlerLogs(t, db)

	cases := []string{
		"?limit=abc",
		"?limit=0",
		"?limit=-1",
		"?offset=-1",
		"?offset=xyz",
		"?action=bogus",
		"?suspicious=maybe",
		"?from=not-a-time",
		"?to=2024-13-40",
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/logs"+q, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("query %q: expected 400, got %d (body: %s)", q, w.Code, w.Body.String())
			}
		})
	}
}

func TestGetQueryLogs_TimeRange(t *testing.T) {
	r, db := setupLogTestHandler(t)
	seedHandlerLogs(t, db)

	// Rows are at 12:00..12:04 UTC. Window 12:01..12:03 -> 3 rows.
	from := "2024-01-01T12:01:00Z"
	to := "2024-01-01T12:03:00Z"
	w, body := doGET(t, r, "/api/v1/analytics/logs?from="+from+"&to="+to)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body.Data.PageInfo.Total != 3 {
		t.Errorf("expected 3 rows in time window, got %d", body.Data.PageInfo.Total)
	}
}

func TestGetQueryLogs_LimitClamped(t *testing.T) {
	r, db := setupLogTestHandler(t)
	seedHandlerLogs(t, db)

	// A huge limit must be clamped to MaxQueryLogPageSize in the reported page info.
	_, body := doGET(t, r, "/api/v1/analytics/logs?limit=100000")
	if body.Data.PageInfo.Limit != repositories.MaxQueryLogPageSize {
		t.Errorf("expected clamped limit %d, got %d", repositories.MaxQueryLogPageSize, body.Data.PageInfo.Limit)
	}
}
