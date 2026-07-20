// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"strings"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// seedQueryLogs inserts a deterministic set of rows with explicit, strictly
// increasing timestamps so ordering and paging are reproducible. Rows are
// returned oldest-first (index 0 is the oldest).
func seedQueryLogs(t *testing.T, db *gorm.DB) []models.DNSQuery {
	t.Helper()
	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	rows := []models.DNSQuery{
		{Domain: "ads.example.com", ClientIP: "10.0.0.1", Action: "block", IsSuspicious: false},
		{Domain: "good.org", ClientIP: "10.0.0.1", Action: "allow", IsSuspicious: false},
		{Domain: "tracker.ads.net", ClientIP: "10.0.0.2", Action: "block", IsSuspicious: false},
		{Domain: "malware.bad", ClientIP: "10.0.0.2", Action: "flagged", IsSuspicious: true},
		{Domain: "portal.example.com", ClientIP: "10.0.0.1", Action: "redirect", IsSuspicious: false},
		{Domain: "phish.evil", ClientIP: "10.0.0.3", Action: "flagged", IsSuspicious: true},
		{Domain: "cdn.good.org", ClientIP: "10.0.0.2", Action: "allow", IsSuspicious: false},
		{Domain: "news.example.com", ClientIP: "10.0.0.1", Action: "allow", IsSuspicious: false},
	}
	for i := range rows {
		rows[i].Timestamp = base.Add(time.Duration(i) * time.Minute)
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("failed to seed row %d: %v", i, err)
		}
	}
	return rows
}

func TestClampQueryLogPageSize(t *testing.T) {
	tests := []struct {
		in   int
		want int
	}{
		{0, DefaultQueryLogPageSize},
		{-5, DefaultQueryLogPageSize},
		{1, 1},
		{50, 50},
		{MaxQueryLogPageSize, MaxQueryLogPageSize},
		{MaxQueryLogPageSize + 1, MaxQueryLogPageSize},
		{100000, MaxQueryLogPageSize},
	}
	for _, tt := range tests {
		if got := ClampQueryLogPageSize(tt.in); got != tt.want {
			t.Errorf("ClampQueryLogPageSize(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestQueryLogRepo_List_NewestFirst(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	items, total, err := repo.List(QueryLogFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 8 {
		t.Fatalf("expected total 8, got %d", total)
	}
	if len(items) != 8 {
		t.Fatalf("expected 8 items, got %d", len(items))
	}
	// Newest row (seeded last) is "news.example.com".
	if items[0].Domain != "news.example.com" {
		t.Errorf("expected newest first (news.example.com), got %q", items[0].Domain)
	}
	// Verify strictly descending timestamps.
	for i := 1; i < len(items); i++ {
		if items[i-1].Timestamp.Before(items[i].Timestamp) {
			t.Errorf("results not ordered newest-first at index %d", i)
		}
	}
}

func TestQueryLogRepo_List_Pagination(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	// Page 1: first 3.
	page1, total, err := repo.List(QueryLogFilter{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatal(err)
	}
	if total != 8 {
		t.Fatalf("expected total 8, got %d", total)
	}
	if len(page1) != 3 {
		t.Fatalf("expected 3 items on page 1, got %d", len(page1))
	}

	// Page 2: next 3.
	page2, _, err := repo.List(QueryLogFilter{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 3 {
		t.Fatalf("expected 3 items on page 2, got %d", len(page2))
	}

	// Page 3: remaining 2.
	page3, _, err := repo.List(QueryLogFilter{Limit: 3, Offset: 6})
	if err != nil {
		t.Fatal(err)
	}
	if len(page3) != 2 {
		t.Fatalf("expected 2 items on page 3, got %d", len(page3))
	}

	// Pages must not overlap.
	seen := map[uint]bool{}
	for _, p := range [][]models.DNSQuery{page1, page2, page3} {
		for _, row := range p {
			if seen[row.ID] {
				t.Errorf("row ID %d appeared on more than one page", row.ID)
			}
			seen[row.ID] = true
		}
	}
	if len(seen) != 8 {
		t.Errorf("expected 8 distinct rows across pages, got %d", len(seen))
	}
}

func TestQueryLogRepo_List_OffsetBeyondEnd(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	items, total, err := repo.List(QueryLogFilter{Limit: 5, Offset: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 8 {
		t.Errorf("expected total 8 regardless of offset, got %d", total)
	}
	if len(items) != 0 {
		t.Errorf("expected 0 items past the end, got %d", len(items))
	}
}

func TestQueryLogRepo_List_DefaultAndNegativeBounds(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	// Limit 0 -> default page size; negative offset -> treated as 0.
	items, total, err := repo.List(QueryLogFilter{Limit: 0, Offset: -10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 8 {
		t.Fatalf("expected total 8, got %d", total)
	}
	// Only 8 rows exist, all fit under the default page size.
	if len(items) != 8 {
		t.Errorf("expected all 8 rows with default page size, got %d", len(items))
	}
}

func TestQueryLogRepo_List_FilterClientIP(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	items, total, err := repo.List(QueryLogFilter{ClientIP: "10.0.0.1", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Errorf("expected 4 rows for 10.0.0.1, got %d", total)
	}
	for _, it := range items {
		if it.ClientIP != "10.0.0.1" {
			t.Errorf("unexpected client IP %q in filtered result", it.ClientIP)
		}
	}
}

func TestQueryLogRepo_List_FilterAction(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	cases := map[string]int64{
		"block":    2,
		"allow":    3,
		"flagged":  2,
		"redirect": 1,
	}
	for action, want := range cases {
		items, total, err := repo.List(QueryLogFilter{Action: action, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if total != want {
			t.Errorf("action %q: expected %d rows, got %d", action, want, total)
		}
		for _, it := range items {
			if it.Action != action {
				t.Errorf("action %q filter returned row with action %q", action, it.Action)
			}
		}
	}
}

func TestQueryLogRepo_List_FilterDomainSubstring(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	// "example.com" matches ads/portal/news.example.com -> 3 rows.
	items, total, err := repo.List(QueryLogFilter{Domain: "example.com", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("expected 3 rows matching 'example.com', got %d", total)
	}
	for _, it := range items {
		if !strings.Contains(it.Domain, "example.com") {
			t.Errorf("row %q does not contain substring 'example.com'", it.Domain)
		}
	}

	// "ads" is a substring of ads.example.com and tracker.ads.net -> 2 rows.
	_, total, err = repo.List(QueryLogFilter{Domain: "ads", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("expected 2 rows matching substring 'ads', got %d", total)
	}
}

func TestQueryLogRepo_List_FilterSuspiciousOnly(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	items, total, err := repo.List(QueryLogFilter{SuspiciousOnly: true, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("expected 2 suspicious rows, got %d", total)
	}
	for _, it := range items {
		if !it.IsSuspicious {
			t.Errorf("suspicious filter returned non-suspicious row %q", it.Domain)
		}
	}
}

func TestQueryLogRepo_List_FilterTimeRange(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	// Inclusive window covering rows at minute 2..4 (3 rows).
	from := base.Add(2 * time.Minute)
	to := base.Add(4 * time.Minute)

	items, total, err := repo.List(QueryLogFilter{From: &from, To: &to, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("expected 3 rows in time window, got %d", total)
	}
	for _, it := range items {
		if it.Timestamp.Before(from) || it.Timestamp.After(to) {
			t.Errorf("row timestamp %v outside window [%v, %v]", it.Timestamp, from, to)
		}
	}
}

func TestQueryLogRepo_List_CombinedFilters(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	seedQueryLogs(t, db)

	// client 10.0.0.1 AND action allow -> good.org, news.example.com (2 rows).
	items, total, err := repo.List(QueryLogFilter{
		ClientIP: "10.0.0.1",
		Action:   "allow",
		Limit:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("expected 2 rows for combined filter, got %d", total)
	}
	for _, it := range items {
		if it.ClientIP != "10.0.0.1" || it.Action != "allow" {
			t.Errorf("combined filter returned mismatched row: %+v", it)
		}
	}
}
