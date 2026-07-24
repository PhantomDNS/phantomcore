package repositories

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.BlocklistSource{},
		&models.BlocklistSnapshot{},
		&models.BlocklistEntry{},
		&models.DNSQuery{},
		&models.Statistics{},
		&models.SystemState{},
		&models.Policy{},
	); err != nil {
		t.Fatalf("failed to migrate test db: %v", err)
	}
	return db
}

// --- Blocklist Repository ---

func TestBlocklistRepo_IsBlocked(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	// Insert a blocklist entry
	db.Create(&models.BlocklistEntry{Domain: "blocked.com", SourceID: "test"})

	blocked, err := repo.IsBlocked("blocked.com")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Error("expected blocked.com to be blocked")
	}

	blocked, err = repo.IsBlocked("allowed.com")
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("expected allowed.com to not be blocked")
	}
}

func TestBlocklistRepo_IsBlocked_Normalization(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	db.Create(&models.BlocklistEntry{Domain: "example.com", SourceID: "test"})

	tests := []struct {
		input string
		want  bool
	}{
		{"EXAMPLE.COM", true},
		{"Example.Com.", true},
		{"example.com.", true},
		{"example.com", true},
		{"other.com", false},
	}
	for _, tt := range tests {
		got, err := repo.IsBlocked(tt.input)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("IsBlocked(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestBlocklistRepo_GetAll(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	db.Create(&models.BlocklistEntry{Domain: "a.com", SourceID: "test"})
	db.Create(&models.BlocklistEntry{Domain: "b.com", SourceID: "test"})

	domains, err := repo.GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}
}

func TestBlocklistRepo_SaveSnapshotWithEntries(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	src := models.BlocklistSource{
		ID: "test-src", Name: "Test", URL: "http://example.com", Format: "hosts",
		Enabled: true, CreatedAt: time.Now(),
	}
	db.Create(&src)

	entries := []models.BlocklistEntry{
		{Domain: "a.com", SourceID: "test-src", Category: "ads"},
		{Domain: "b.com", SourceID: "test-src", Category: "ads"},
		{Domain: "c.com", SourceID: "test-src", Category: "ads"},
	}

	snap, err := repo.SaveSnapshotWithEntries(src, "abc123", entries)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Size != 3 {
		t.Errorf("expected snapshot size 3, got %d", snap.Size)
	}
	if snap.Checksum != "abc123" {
		t.Errorf("expected checksum abc123, got %s", snap.Checksum)
	}

	// Verify entries are persisted
	blocked, _ := repo.IsBlocked("a.com")
	if !blocked {
		t.Error("expected a.com to be blocked after snapshot save")
	}
}

func TestBlocklistRepo_GetRecentSnapshots(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	base := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	// Insert three snapshots for src-a (oldest -> newest) plus one for src-b.
	db.Create(&models.BlocklistSnapshot{SourceID: "src-a", Size: 100, CreatedAt: base})
	db.Create(&models.BlocklistSnapshot{SourceID: "src-a", Size: 200, CreatedAt: base.Add(time.Hour)})
	db.Create(&models.BlocklistSnapshot{SourceID: "src-a", Size: 300, CreatedAt: base.Add(2 * time.Hour)})
	db.Create(&models.BlocklistSnapshot{SourceID: "src-b", Size: 999, CreatedAt: base})

	// limit=2 returns the two newest for src-a, most recent first.
	snaps, err := repo.GetRecentSnapshots("src-a", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snaps))
	}
	if snaps[0].Size != 300 || snaps[1].Size != 200 {
		t.Fatalf("expected newest-first [300,200], got [%d,%d]", snaps[0].Size, snaps[1].Size)
	}

	// limit<=0 returns all snapshots for the source, and only that source.
	all, err := repo.GetRecentSnapshots("src-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 snapshots for src-a, got %d", len(all))
	}

	// A source with no snapshots returns an empty slice, not an error.
	none, err := repo.GetRecentSnapshots("missing", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 snapshots for missing source, got %d", len(none))
	}
}

func TestBlocklistRepo_CountSnapshots(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	// Fresh DB — no snapshots yet (drives the offline bundle seed decision).
	n, err := repo.CountSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 snapshots on fresh DB, got %d", n)
	}

	src := models.BlocklistSource{ID: "src1", Name: "Test", URL: "http://x", Format: "hosts", Enabled: true, CreatedAt: time.Now()}
	db.Create(&src)
	if _, err := repo.SaveSnapshotWithEntries(src, "hash", []models.BlocklistEntry{{Domain: "a.com", SourceID: "src1"}}); err != nil {
		t.Fatal(err)
	}

	n, err = repo.CountSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 snapshot after save, got %d", n)
	}
}

func TestBlocklistRepo_GetAll_Empty(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	domains, err := repo.GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 0 {
		t.Errorf("expected 0 domains, got %d", len(domains))
	}
}

// --- Query Log Repository ---

func TestQueryLogRepo_SaveAndListRecent(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)

	if err := repo.Save(&models.DNSQuery{Domain: "first.com", ClientIP: "1.2.3.4", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(&models.DNSQuery{Domain: "second.com", ClientIP: "1.2.3.4", Action: "block"}); err != nil {
		t.Fatal(err)
	}

	queries, err := repo.ListRecent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 {
		t.Errorf("expected 2 queries, got %d", len(queries))
	}
	// Most recent first
	if queries[0].Domain != "second.com" {
		t.Errorf("expected most recent first, got %q", queries[0].Domain)
	}
}

func TestQueryLogRepo_ListRecent_Limit(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)

	for i := 0; i < 5; i++ {
		if err := repo.Save(&models.DNSQuery{Domain: "test.com", ClientIP: "1.2.3.4", Action: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	queries, err := repo.ListRecent(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 3 {
		t.Errorf("expected 3 queries with limit, got %d", len(queries))
	}
}

// --- Statistics Repository ---

func TestStatisticsRepo_IncrementCounter(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormStatisticsRepo(db)

	for _, action := range []string{"allow", "allow", "block", "redirect"} {
		if err := repo.IncrementCounter(action); err != nil {
			t.Fatal(err)
		}
	}

	var stats models.Statistics
	db.First(&stats, 1)

	if stats.TotalQueries != 4 {
		t.Errorf("expected 4 total, got %d", stats.TotalQueries)
	}
	if stats.AllowedQueries != 2 {
		t.Errorf("expected 2 allowed, got %d", stats.AllowedQueries)
	}
	if stats.BlockedQueries != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.BlockedQueries)
	}
	if stats.RedirectedQueries != 1 {
		t.Errorf("expected 1 redirected, got %d", stats.RedirectedQueries)
	}
}

func TestStatisticsRepo_UnknownAction(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormStatisticsRepo(db)

	if err := repo.IncrementCounter("something_weird"); err != nil {
		t.Fatal(err)
	}

	var stats models.Statistics
	db.First(&stats, 1)

	// Unknown action still increments total
	if stats.TotalQueries != 1 {
		t.Errorf("expected 1 total for unknown action, got %d", stats.TotalQueries)
	}
	if stats.AllowedQueries != 0 || stats.BlockedQueries != 0 || stats.RedirectedQueries != 0 {
		t.Error("unknown action should not increment specific counters")
	}
}

// --- System State Repository ---

func TestSystemStateRepo_GetCreatesDefault(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSystemStateRepo(db)

	state, err := repo.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !state.DNSEnabled {
		t.Error("expected DNSEnabled=true by default")
	}
	if !state.PolicyEnabled {
		t.Error("expected PolicyEnabled=true by default")
	}
}

func TestSystemStateRepo_SetDNSEnabled(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSystemStateRepo(db)

	// Create initial state
	if _, err := repo.Get(); err != nil {
		t.Fatal(err)
	}

	if err := repo.SetDNSEnabled(true); err != nil {
		t.Fatal(err)
	}

	state, _ := repo.Get()
	if !state.DNSEnabled {
		t.Error("expected DNSEnabled=true after setting")
	}
}

func TestSystemStateRepo_SetPolicyEnabled(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSystemStateRepo(db)

	if _, err := repo.Get(); err != nil {
		t.Fatal(err)
	}

	if err := repo.SetPolicyEnabled(true); err != nil {
		t.Fatal(err)
	}

	state, _ := repo.Get()
	if !state.PolicyEnabled {
		t.Error("expected PolicyEnabled=true after setting")
	}
}

func TestSystemStateRepo_GetIdempotent(t *testing.T) {
	db := setupTestDB(t)
	repo := NewSystemStateRepo(db)

	s1, _ := repo.Get()
	s2, _ := repo.Get()
	if s1.ID != s2.ID {
		t.Error("expected same row on repeated Get()")
	}
}

// --- Policy Repository ---

func TestPolicyRepo_CreateAndGet(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPolicyRepo(db)

	p := &models.Policy{
		ID: "block-ads", Name: "Block Ads", Action: "BLOCK",
		Domains: `["ads.example.com","tracker.com"]`, Priority: 100, Enabled: true,
	}
	if err := repo.Create(p); err != nil {
		t.Fatal(err)
	}

	got, err := repo.GetByID("block-ads")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Block Ads" {
		t.Errorf("expected name 'Block Ads', got %q", got.Name)
	}
	if got.Priority != 100 {
		t.Errorf("expected priority 100, got %d", got.Priority)
	}
}

func TestPolicyRepo_List(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPolicyRepo(db)

	if err := repo.Create(&models.Policy{ID: "p1", Name: "P1", Action: "BLOCK", Priority: 10, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(&models.Policy{ID: "p2", Name: "P2", Action: "ALLOW", Priority: 200, Enabled: false}); err != nil {
		t.Fatal(err)
	}

	list, err := repo.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(list))
	}
	// Should be ordered by priority desc
	if list[0].ID != "p2" {
		t.Errorf("expected highest priority first, got %s", list[0].ID)
	}
}

func TestPolicyRepo_Delete(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPolicyRepo(db)

	if err := repo.Create(&models.Policy{ID: "del-me", Name: "Del", Action: "BLOCK"}); err != nil {
		t.Fatal(err)
	}

	if err := repo.Delete("del-me"); err != nil {
		t.Fatal(err)
	}

	_, err := repo.GetByID("del-me")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestPolicyRepo_DeleteNotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPolicyRepo(db)

	err := repo.Delete("nonexistent")
	if err == nil {
		t.Error("expected error deleting nonexistent policy")
	}
}

// --- Blocklist Source Methods ---

func TestBlocklistRepo_SourceCRUD(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	src := &models.BlocklistSource{
		ID: "steven-black", Name: "StevenBlack", URL: "http://example.com/hosts",
		Format: "hosts", Category: "ads", Enabled: true, CreatedAt: time.Now(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatal(err)
	}

	// List
	sources, err := repo.ListSources()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}

	// Get
	got, err := repo.GetSource("steven-black")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "StevenBlack" {
		t.Errorf("expected name StevenBlack, got %q", got.Name)
	}

	// Count entries (should be 0)
	count, err := repo.CountEntriesBySource("steven-black")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries, got %d", count)
	}

	// Delete
	if err := repo.DeleteSource("steven-black"); err != nil {
		t.Fatal(err)
	}
	sources, _ = repo.ListSources()
	if len(sources) != 0 {
		t.Error("expected 0 sources after delete")
	}
}

func TestBlocklistRepo_DeleteSourceCascades(t *testing.T) {
	db := setupTestDB(t)
	repo := NewBlocklistRepo(db)

	src := &models.BlocklistSource{ID: "src1", Name: "Test", URL: "http://x", Format: "hosts", Enabled: true, CreatedAt: time.Now()}
	if err := repo.CreateSource(src); err != nil {
		t.Fatal(err)
	}

	entries := []models.BlocklistEntry{
		{Domain: "a.com", SourceID: "src1"},
		{Domain: "b.com", SourceID: "src1"},
	}
	if _, err := repo.SaveSnapshotWithEntries(*src, "hash", entries); err != nil {
		t.Fatal(err)
	}

	// Verify entries exist
	count, _ := repo.CountEntriesBySource("src1")
	if count != 2 {
		t.Fatalf("expected 2 entries before delete, got %d", count)
	}

	// Delete source — should cascade
	if err := repo.DeleteSource("src1"); err != nil {
		t.Fatal(err)
	}

	count, _ = repo.CountEntriesBySource("src1")
	if count != 0 {
		t.Errorf("expected 0 entries after cascade delete, got %d", count)
	}
}
