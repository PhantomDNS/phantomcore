// SPDX-License-Identifier: GPL-3.0-or-later
package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
	glog "gorm.io/gorm/logger"
)

func newAggRepo(t *testing.T) *repositories.BlocklistRepo {
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
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repositories.NewBlocklistRepo(db)
}

func hostsServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

// TestAggregateFeeds_DedupAcrossFeeds verifies that enabling a category with two feeds
// that share a domain stores the union once — the domain overlapping both feeds is not
// double-stored.
func TestAggregateFeeds_DedupAcrossFeeds(t *testing.T) {
	repo := newAggRepo(t)
	engine := NewEngine(repo)

	// feedA: a, shared   feedB: shared, b  → union {a, shared, b} = 3 unique.
	feedA := hostsServer(t, "0.0.0.0 a.example.com\n0.0.0.0 shared.example.com\n")
	defer feedA.Close()
	feedB := hostsServer(t, "0.0.0.0 shared.example.com\n0.0.0.0 b.example.com\n")
	defer feedB.Close()

	feeds := []Feed{
		{Name: "A", URL: feedA.URL, Format: "hosts"},
		{Name: "B", URL: feedB.URL, Format: "hosts"},
	}

	srcID := CategorySourceID("malware")
	n, err := engine.AggregateFeeds(context.Background(), srcID, "Category: malware", "malware", feeds)
	if err != nil {
		t.Fatalf("AggregateFeeds: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 deduped domains, got %d", n)
	}

	// The DB must hold exactly 3 entries for the aggregate source (dedup persisted).
	count, err := repo.CountEntriesBySource(srcID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 persisted entries, got %d", count)
	}

	for _, d := range []string{"a.example.com", "shared.example.com", "b.example.com"} {
		if blocked, _ := repo.IsBlocked(d); !blocked {
			t.Errorf("expected %s blocked after aggregation", d)
		}
	}
}

// TestAggregateFeeds_ToleratesFailedFeed verifies one failing feed (here, an
// unregistered format) does not fail the whole category as long as another feed
// succeeds.
func TestAggregateFeeds_ToleratesFailedFeed(t *testing.T) {
	repo := newAggRepo(t)
	engine := NewEngine(repo)

	bad := hostsServer(t, "0.0.0.0 ignored.example.com\n")
	defer bad.Close()
	good := hostsServer(t, "0.0.0.0 good.example.com\n")
	defer good.Close()

	feeds := []Feed{
		{Name: "Bad", URL: bad.URL, Format: "no-such-format"}, // parser lookup fails
		{Name: "Good", URL: good.URL, Format: "hosts"},
	}

	n, err := engine.AggregateFeeds(context.Background(), CategorySourceID("phishing"), "Category: phishing", "phishing", feeds)
	if err != nil {
		t.Fatalf("expected success despite one failed feed, got: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 domain from the good feed, got %d", n)
	}
	if blocked, _ := repo.IsBlocked("good.example.com"); !blocked {
		t.Error("expected good.example.com blocked")
	}
}

// TestStoreDomains_DedupsBundle verifies a collection bundle is deduped and normalized.
func TestStoreDomains_DedupsBundle(t *testing.T) {
	repo := newAggRepo(t)
	engine := NewEngine(repo)

	srcID := CollectionSourceID("tiktok")
	// "TikTok.com" and "tiktok.com." collapse to one; blank is dropped.
	n, err := engine.StoreDomains(srcID, "Collection: TikTok", "tiktok",
		[]string{"tiktok.com", "TikTok.com", "tiktok.com.", "tiktokcdn.com", "  "})
	if err != nil {
		t.Fatalf("StoreDomains: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 unique domains, got %d", n)
	}
	if blocked, _ := repo.IsBlocked("tiktok.com"); !blocked {
		t.Error("expected tiktok.com blocked")
	}
}
