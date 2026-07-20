// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// seedAnalytics inserts a deterministic set of rows spread across known clients,
// actions, and hours so aggregate results are reproducible.
//
// Layout (all on 2024-01-01 UTC):
//
//	10.0.0.1: 5 queries -> 3 block (ads/track/malv), 2 allow (good/news)
//	10.0.0.2: 3 queries -> 1 block (ads2), 2 allow (cdn/api)
//	10.0.0.3: 1 query   -> 1 flagged (phish)
//
// Block totals per domain: "ads.example.com" appears blocked twice.
func seedAnalytics(t *testing.T, db *gorm.DB) {
	t.Helper()
	rows := []models.DNSQuery{
		// client 1 — hour 10
		{Domain: "ads.example.com", ClientIP: "10.0.0.1", Action: "block", Timestamp: at(10, 0)},
		{Domain: "track.example.com", ClientIP: "10.0.0.1", Action: "block", Timestamp: at(10, 5)},
		{Domain: "good.org", ClientIP: "10.0.0.1", Action: "allow", Timestamp: at(10, 10)},
		// client 1 — hour 11
		{Domain: "malware.bad", ClientIP: "10.0.0.1", Action: "block", Timestamp: at(11, 0)},
		{Domain: "news.example.com", ClientIP: "10.0.0.1", Action: "allow", Timestamp: at(11, 30)},
		// client 2 — hour 10
		{Domain: "ads.example.com", ClientIP: "10.0.0.2", Action: "block", Timestamp: at(10, 15)},
		{Domain: "cdn.good.org", ClientIP: "10.0.0.2", Action: "allow", Timestamp: at(10, 20)},
		// client 2 — hour 12
		{Domain: "api.good.org", ClientIP: "10.0.0.2", Action: "allow", Timestamp: at(12, 0)},
		// client 3 — hour 11
		{Domain: "phish.evil", ClientIP: "10.0.0.3", Action: "flagged", IsSuspicious: true, Timestamp: at(11, 45)},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("failed to seed row %d: %v", i, err)
		}
	}
}

// at returns a fixed 2024-01-01 timestamp at the given hour/minute in UTC.
func at(hour, min int) time.Time {
	return time.Date(2024, 1, 1, hour, min, 0, 0, time.UTC)
}

func TestClampAnalyticsTopN(t *testing.T) {
	tests := []struct {
		in, want int
	}{
		{0, DefaultAnalyticsTopN},
		{-3, DefaultAnalyticsTopN},
		{1, 1},
		{10, 10},
		{MaxAnalyticsTopN, MaxAnalyticsTopN},
		{MaxAnalyticsTopN + 1, MaxAnalyticsTopN},
		{99999, MaxAnalyticsTopN},
	}
	for _, tt := range tests {
		if got := ClampAnalyticsTopN(tt.in); got != tt.want {
			t.Errorf("ClampAnalyticsTopN(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestAnalytics_TopClients(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	got, err := repo.TopClients(AnalyticsWindow{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	want := []ClientActivity{
		{ClientIP: "10.0.0.1", Total: 5, Blocked: 3},
		{ClientIP: "10.0.0.2", Total: 3, Blocked: 1},
		{ClientIP: "10.0.0.3", Total: 1, Blocked: 0},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d clients, got %d (%+v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestAnalytics_TopClients_TopNCap(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	// Top-1 must return only the busiest client.
	got, err := repo.TopClients(AnalyticsWindow{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 client with Limit=1, got %d", len(got))
	}
	if got[0].ClientIP != "10.0.0.1" {
		t.Errorf("expected busiest client 10.0.0.1, got %q", got[0].ClientIP)
	}

	// Limit 0 falls back to the default (>= 3 clients here).
	all, err := repo.TopClients(AnalyticsWindow{Limit: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 clients with default top-N, got %d", len(all))
	}
}

func TestAnalytics_TopBlockedDomains(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	got, err := repo.TopBlockedDomains(AnalyticsWindow{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	// Blocked domains: ads.example.com x2, track.example.com x1, malware.bad x1.
	if len(got) != 3 {
		t.Fatalf("expected 3 blocked domains, got %d (%+v)", len(got), got)
	}
	if got[0].Domain != "ads.example.com" || got[0].Count != 2 {
		t.Errorf("expected top blocked ads.example.com=2, got %+v", got[0])
	}
	// Non-block dispositions must not appear.
	for _, d := range got {
		if d.Domain == "good.org" || d.Domain == "phish.evil" {
			t.Errorf("non-blocked domain %q leaked into top-blocked", d.Domain)
		}
	}
}

func TestAnalytics_CategoryBreakdown(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	got, err := repo.CategoryBreakdown(AnalyticsWindow{})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, c := range got {
		counts[c.Category] = c.Count
	}
	want := map[string]int64{"block": 4, "allow": 4, "flagged": 1}
	for cat, n := range want {
		if counts[cat] != n {
			t.Errorf("category %q: expected %d, got %d", cat, n, counts[cat])
		}
	}
	// Ordered by count desc: first row must be one of the count-4 categories.
	if len(got) > 0 && got[0].Count != 4 {
		t.Errorf("expected highest count first, got %+v", got[0])
	}
}

func TestAnalytics_ClientTimeline(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	got, err := repo.ClientTimeline("10.0.0.1", AnalyticsWindow{})
	if err != nil {
		t.Fatal(err)
	}
	// client 1 has activity in hour 10 (3 queries, 2 blocked) and hour 11 (2, 1).
	if len(got) != 2 {
		t.Fatalf("expected 2 hourly buckets, got %d (%+v)", len(got), got)
	}
	if !got[0].Bucket.Equal(at(10, 0)) {
		t.Errorf("expected first bucket at hour 10, got %v", got[0].Bucket)
	}
	if got[0].Total != 3 || got[0].Blocked != 2 {
		t.Errorf("hour 10: expected total=3 blocked=2, got total=%d blocked=%d", got[0].Total, got[0].Blocked)
	}
	if !got[1].Bucket.Equal(at(11, 0)) {
		t.Errorf("expected second bucket at hour 11, got %v", got[1].Bucket)
	}
	if got[1].Total != 2 || got[1].Blocked != 1 {
		t.Errorf("hour 11: expected total=2 blocked=1, got total=%d blocked=%d", got[1].Total, got[1].Blocked)
	}
	// Buckets must be oldest-first.
	if got[0].Bucket.After(got[1].Bucket) {
		t.Errorf("timeline not ordered oldest-first")
	}
}

func TestAnalytics_ClientTimeline_UnknownClient(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	got, err := repo.ClientTimeline("192.168.1.1", AnalyticsWindow{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty timeline for unknown client, got %d buckets", len(got))
	}
}

func TestAnalytics_CategoryHourHeatmap(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	got, err := repo.CategoryHourHeatmap(AnalyticsWindow{})
	if err != nil {
		t.Fatal(err)
	}
	// Index by hour|category for assertions.
	type key struct {
		h int
		c string
	}
	cells := map[key]int64{}
	for _, cell := range got {
		cells[key{cell.Hour, cell.Category}] = cell.Count
	}
	// Hour 10: block x3 (ads1, track, ads2), allow x2 (good, cdn).
	if cells[key{10, "block"}] != 3 {
		t.Errorf("hour 10 block: expected 3, got %d", cells[key{10, "block"}])
	}
	if cells[key{10, "allow"}] != 2 {
		t.Errorf("hour 10 allow: expected 2, got %d", cells[key{10, "allow"}])
	}
	// Hour 11: block x1 (malware), allow x1 (news), flagged x1 (phish).
	if cells[key{11, "block"}] != 1 || cells[key{11, "allow"}] != 1 || cells[key{11, "flagged"}] != 1 {
		t.Errorf("hour 11 cells wrong: %+v", got)
	}
	// Hour 12: allow x1 (api).
	if cells[key{12, "allow"}] != 1 {
		t.Errorf("hour 12 allow: expected 1, got %d", cells[key{12, "allow"}])
	}
	// Ordering: hours ascending.
	for i := 1; i < len(got); i++ {
		if got[i-1].Hour > got[i].Hour {
			t.Errorf("heatmap not ordered by hour ascending at index %d", i)
		}
	}
}

func TestAnalytics_WindowTimeRange(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	// Restrict to hour 10 only: [10:00, 10:59].
	from := at(10, 0)
	to := at(10, 59)
	w := AnalyticsWindow{From: &from, To: &to, Limit: 10}

	cats, err := repo.CategoryBreakdown(w)
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	for _, c := range cats {
		total += c.Count
	}
	// Hour 10 has 5 rows (3 block + 2 allow).
	if total != 5 {
		t.Errorf("expected 5 rows in hour-10 window, got %d", total)
	}

	clients, err := repo.TopClients(w)
	if err != nil {
		t.Fatal(err)
	}
	// Only clients active in hour 10: 10.0.0.1 (3) and 10.0.0.2 (2).
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients in window, got %d (%+v)", len(clients), clients)
	}
	if clients[0].ClientIP != "10.0.0.1" || clients[0].Total != 3 {
		t.Errorf("expected 10.0.0.1 total=3 in window, got %+v", clients[0])
	}
}

func TestGatherWindowStats(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedAnalytics(t, db)

	stats, err := repo.GatherWindowStats(AnalyticsWindow{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 9 {
		t.Errorf("expected total 9, got %d", stats.Total)
	}
	if stats.Blocked != 4 {
		t.Errorf("expected blocked 4, got %d", stats.Blocked)
	}
	if len(stats.Clients) != 3 {
		t.Errorf("expected 3 clients, got %d", len(stats.Clients))
	}
	// BlockedRate = 4/9 * 100 ~= 44.4%.
	if r := stats.BlockedRate(); r < 44.0 || r > 45.0 {
		t.Errorf("expected blocked rate ~44.4, got %f", r)
	}
}

func TestAnomalyDigestBetween_Integration(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)

	// Prior window (hour 8): 4 queries, 0 blocked, client A dominant.
	prior := []models.DNSQuery{
		{Domain: "a.com", ClientIP: "10.0.0.1", Action: "allow", Timestamp: at(8, 0)},
		{Domain: "b.com", ClientIP: "10.0.0.1", Action: "allow", Timestamp: at(8, 5)},
		{Domain: "c.com", ClientIP: "10.0.0.1", Action: "allow", Timestamp: at(8, 10)},
		{Domain: "d.com", ClientIP: "10.0.0.2", Action: "allow", Timestamp: at(8, 15)},
	}
	// Current window (hour 9): 8 queries, 6 blocked -> blocked-rate spike.
	current := []models.DNSQuery{}
	for i := 0; i < 6; i++ {
		current = append(current, models.DNSQuery{Domain: "bad.com", ClientIP: "10.0.0.9", Action: "block", Timestamp: at(9, i)})
	}
	current = append(current,
		models.DNSQuery{Domain: "ok.com", ClientIP: "10.0.0.9", Action: "allow", Timestamp: at(9, 30)},
		models.DNSQuery{Domain: "ok2.com", ClientIP: "10.0.0.9", Action: "allow", Timestamp: at(9, 31)},
	)
	for _, r := range append(prior, current...) {
		rr := r
		if err := db.Create(&rr).Error; err != nil {
			t.Fatal(err)
		}
	}

	curFrom, curTo := at(9, 0), at(9, 59)
	priFrom, priTo := at(8, 0), at(8, 59)
	digest, err := repo.AnomalyDigestBetween(
		AnalyticsWindow{From: &curFrom, To: &curTo, Limit: 10},
		AnalyticsWindow{From: &priFrom, To: &priTo, Limit: 10},
		// Lower the surge floor so the 8-query seed is enough to exercise the
		// surge path with a lean fixture.
		AnomalyThresholds{ClientSurgeMinQueries: 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	if digest.TotalCurrent != 8 || digest.TotalPrior != 4 {
		t.Errorf("expected totals cur=8 prior=4, got cur=%d prior=%d", digest.TotalCurrent, digest.TotalPrior)
	}
	// Current blocked-rate 6/8=75%, prior 0% -> spike.
	if !digest.BlockedRateSpike {
		t.Errorf("expected blocked-rate spike, got delta=%f", digest.BlockedRateDeltaPoints)
	}
	// 10.0.0.9 went 0 -> 8 queries: must be reported as a surge.
	found := false
	for _, s := range digest.SurgingClients {
		if s.ClientIP == "10.0.0.9" {
			found = true
			if s.Current != 8 || s.Prior != 0 {
				t.Errorf("surge for 10.0.0.9 wrong: %+v", s)
			}
		}
	}
	if !found {
		t.Errorf("expected 10.0.0.9 flagged as surging, got %+v", digest.SurgingClients)
	}
}
