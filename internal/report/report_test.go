// SPDX-License-Identifier: GPL-3.0-or-later
package report_test

import (
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"

	"github.com/lopster568/phantomDNS/internal/report"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: glogger.Default.LogMode(glogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(&models.DNSQuery{}, &models.BlocklistEntry{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// seedWindow inserts a deterministic set of query-log rows: 7 blocks
// (2 of them suspicious threats) and 5 allows inside the window, plus one
// block dated before the window that must be excluded from every aggregate.
func seedWindow(t *testing.T, db *gorm.DB) (from, to time.Time) {
	t.Helper()
	base := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)

	rows := []models.DNSQuery{
		{Domain: "ads.example.com", ClientIP: "10.0.0.1", Action: "block", Timestamp: base.Add(1 * time.Minute)},
		{Domain: "ads.example.com", ClientIP: "10.0.0.2", Action: "block", Timestamp: base.Add(2 * time.Minute)},
		{Domain: "ads.example.com", ClientIP: "10.0.0.3", Action: "block", Timestamp: base.Add(3 * time.Minute)},
		{Domain: "tracker.example.net", ClientIP: "10.0.0.1", Action: "block", Timestamp: base.Add(4 * time.Minute)},
		{Domain: "tracker.example.net", ClientIP: "10.0.0.2", Action: "block", Timestamp: base.Add(5 * time.Minute)},
		{Domain: "malware.bad.com", ClientIP: "10.0.0.9", Action: "block", Timestamp: base.Add(6 * time.Minute),
			IsSuspicious: true, ThreatScore: 0.95, ThreatReason: "known malware C2"},
		{Domain: "malware.bad.com", ClientIP: "10.0.0.8", Action: "block", Timestamp: base.Add(7 * time.Minute),
			IsSuspicious: true, ThreatScore: 0.90, DetectionMethod: "heuristic"},
		{Domain: "good.com", ClientIP: "10.0.0.1", Action: "allow", Timestamp: base.Add(8 * time.Minute)},
		{Domain: "good.com", ClientIP: "10.0.0.2", Action: "allow", Timestamp: base.Add(9 * time.Minute)},
		{Domain: "good.com", ClientIP: "10.0.0.3", Action: "allow", Timestamp: base.Add(10 * time.Minute)},
		{Domain: "good.com", ClientIP: "10.0.0.4", Action: "allow", Timestamp: base.Add(11 * time.Minute)},
		{Domain: "safe.org", ClientIP: "10.0.0.5", Action: "allow", Timestamp: base.Add(12 * time.Minute)},
		// Outside the window — must be excluded.
		{Domain: "old.example.com", ClientIP: "10.0.0.1", Action: "block", Timestamp: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed dns query: %v", err)
		}
	}

	entries := []models.BlocklistEntry{
		{Domain: "ads.example.com", SourceID: "s", Category: "advertising"},
		{Domain: "tracker.example.net", SourceID: "s", Category: "tracking"},
		{Domain: "malware.bad.com", SourceID: "s", Category: "malware"},
	}
	for i := range entries {
		if err := db.Create(&entries[i]).Error; err != nil {
			t.Fatalf("seed blocklist entry: %v", err)
		}
	}

	from = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	to = time.Date(2026, 7, 20, 23, 59, 59, 0, time.UTC)
	return from, to
}

func TestGenerate_Aggregates(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewGormQueryLogRepo(db)
	from, to := seedWindow(t, db)

	rep, err := report.Generate(repo, from, to)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if rep.TotalQueries != 12 {
		t.Errorf("TotalQueries = %d, want 12 (out-of-window row must be excluded)", rep.TotalQueries)
	}
	if rep.BlockedQueries != 7 {
		t.Errorf("BlockedQueries = %d, want 7", rep.BlockedQueries)
	}
	if rep.AllowedQueries != 5 {
		t.Errorf("AllowedQueries = %d, want 5", rep.AllowedQueries)
	}
	if rep.ThreatsBlocked != 2 {
		t.Errorf("ThreatsBlocked = %d, want 2", rep.ThreatsBlocked)
	}
	if rep.AdsAndTrackers != 5 {
		t.Errorf("AdsAndTrackers = %d, want 5", rep.AdsAndTrackers)
	}
	// 7/12 * 100 = 58.33...
	if got := rep.BlockRatePercent; got < 58.3 || got > 58.4 {
		t.Errorf("BlockRatePercent = %.4f, want ~58.33", got)
	}
	if rep.Period != report.PeriodWeekly {
		t.Errorf("Period = %q, want weekly", rep.Period)
	}

	// Top blocked domains: ads(3), then the 2-count tie broken by domain name.
	wantDomains := []report.DomainCount{
		{Domain: "ads.example.com", Count: 3},
		{Domain: "malware.bad.com", Count: 2},
		{Domain: "tracker.example.net", Count: 2},
	}
	if len(rep.TopBlockedDomains) != len(wantDomains) {
		t.Fatalf("TopBlockedDomains = %+v, want %+v", rep.TopBlockedDomains, wantDomains)
	}
	for i, w := range wantDomains {
		if rep.TopBlockedDomains[i] != w {
			t.Errorf("TopBlockedDomains[%d] = %+v, want %+v", i, rep.TopBlockedDomains[i], w)
		}
	}

	// Top blocked categories, derived from the blocklist join.
	wantCats := []report.CategoryCount{
		{Category: "advertising", Count: 3},
		{Category: "malware", Count: 2},
		{Category: "tracking", Count: 2},
	}
	if len(rep.TopBlockedCategories) != len(wantCats) {
		t.Fatalf("TopBlockedCategories = %+v, want %+v", rep.TopBlockedCategories, wantCats)
	}
	for i, w := range wantCats {
		if rep.TopBlockedCategories[i] != w {
			t.Errorf("TopBlockedCategories[%d] = %+v, want %+v", i, rep.TopBlockedCategories[i], w)
		}
	}

	// Notable events: both suspicious lookups, highest score first.
	if len(rep.NotableEvents) != 2 {
		t.Fatalf("NotableEvents count = %d, want 2", len(rep.NotableEvents))
	}
	if rep.NotableEvents[0].Domain != "malware.bad.com" || rep.NotableEvents[0].ThreatScore != 0.95 {
		t.Errorf("NotableEvents[0] = %+v, want malware.bad.com @0.95", rep.NotableEvents[0])
	}
	if rep.NotableEvents[0].Reason != "known malware C2" {
		t.Errorf("NotableEvents[0].Reason = %q, want 'known malware C2'", rep.NotableEvents[0].Reason)
	}
	if !rep.NotableEvents[0].Blocked {
		t.Error("NotableEvents[0].Blocked = false, want true")
	}
	// Falls back to DetectionMethod when ThreatReason is empty.
	if rep.NotableEvents[1].Reason != "heuristic" {
		t.Errorf("NotableEvents[1].Reason = %q, want 'heuristic'", rep.NotableEvents[1].Reason)
	}
}

func TestRenderText_ContainsKeyNumbers(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewGormQueryLogRepo(db)
	from, to := seedWindow(t, db)

	rep, err := report.Generate(repo, from, to)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	text := report.RenderText(rep)
	for _, want := range []string{
		"This week",          // period label, capitalized
		"12 DNS requests",    // total
		"blocked 7",          // blocked count
		"58.3",               // block rate
		"5 ads and trackers", // ads = blocked - threats
		"2 malware",          // threats
		"ads.example.com",    // top domain
		"advertising",        // top category
		"malware.bad.com",    // notable event
		"known malware C2",   // notable event reason
	} {
		if !strings.Contains(text, want) {
			t.Errorf("RenderText missing %q\n---\n%s", want, text)
		}
	}
}

func TestRenderHTML_ContainsKeyNumbers(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewGormQueryLogRepo(db)
	from, to := seedWindow(t, db)

	rep, err := report.Generate(repo, from, to)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	html := report.RenderHTML(rep)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"HydraDNS Security Report",
		"<strong>12</strong>",
		"<strong>7</strong>",
		"advertising",
		"malware.bad.com",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("RenderHTML missing %q\n---\n%s", want, html)
		}
	}
}

func TestGenerate_EmptyRange(t *testing.T) {
	db := setupTestDB(t)
	repo := repositories.NewGormQueryLogRepo(db)
	seedWindow(t, db) // data exists, but the query window below has none

	from := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2020, 1, 8, 0, 0, 0, 0, time.UTC)

	rep, err := report.Generate(repo, from, to)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if rep.TotalQueries != 0 || rep.BlockedQueries != 0 {
		t.Errorf("empty range should be zeroed, got total=%d blocked=%d", rep.TotalQueries, rep.BlockedQueries)
	}
	if rep.BlockRatePercent != 0 {
		t.Errorf("empty range block rate = %v, want 0 (no divide-by-zero)", rep.BlockRatePercent)
	}
	if len(rep.TopBlockedDomains) != 0 || len(rep.TopBlockedCategories) != 0 || len(rep.NotableEvents) != 0 {
		t.Error("empty range should have no domains/categories/events")
	}

	text := report.RenderText(rep)
	if !strings.Contains(text, "no DNS activity") {
		t.Errorf("empty RenderText should mention no activity, got:\n%s", text)
	}
	html := report.RenderHTML(rep)
	if !strings.Contains(html, "no DNS activity") {
		t.Errorf("empty RenderHTML should mention no activity, got:\n%s", html)
	}
}

func TestGenerate_NilRepo(t *testing.T) {
	if _, err := report.Generate(nil, time.Now(), time.Now()); err == nil {
		t.Error("Generate(nil, ...) should return an error")
	}
}
