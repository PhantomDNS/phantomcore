// SPDX-License-Identifier: GPL-3.0-or-later
package bundle

import (
	"errors"
	"testing"

	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

// mockBlocklistRepo is a deterministic in-memory stand-in for
// repositories.BlocklistRepository. Only the methods the seeder touches carry
// behaviour; the rest satisfy the interface.
type mockBlocklistRepo struct {
	snapshotCount int64
	countErr      error
	saveErr       error

	saveCalls    int
	savedSource  models.BlocklistSource
	savedEntries []models.BlocklistEntry
}

var _ repositories.BlocklistRepository = (*mockBlocklistRepo)(nil)

func (m *mockBlocklistRepo) CountSnapshots() (int64, error) {
	return m.snapshotCount, m.countErr
}

func (m *mockBlocklistRepo) SaveSnapshotWithEntries(src models.BlocklistSource, checksum string, entries []models.BlocklistEntry) (models.BlocklistSnapshot, error) {
	m.saveCalls++
	m.savedSource = src
	m.savedEntries = entries
	if m.saveErr != nil {
		return models.BlocklistSnapshot{}, m.saveErr
	}
	m.snapshotCount++
	return models.BlocklistSnapshot{ID: uint(m.snapshotCount), SourceID: src.ID, Size: len(entries), Checksum: checksum}, nil
}

// --- unused interface methods ---
func (m *mockBlocklistRepo) GetAll() ([]string, error)                      { return nil, nil }
func (m *mockBlocklistRepo) IsBlocked(string) (bool, error)                 { return false, nil }
func (m *mockBlocklistRepo) ListSources() ([]models.BlocklistSource, error) { return nil, nil }
func (m *mockBlocklistRepo) GetSource(string) (*models.BlocklistSource, error) {
	return nil, nil
}
func (m *mockBlocklistRepo) CreateSource(*models.BlocklistSource) error { return nil }
func (m *mockBlocklistRepo) DeleteSource(string) error                  { return nil }
func (m *mockBlocklistRepo) CountEntriesBySource(string) (int64, error) {
	return 0, nil
}
func (m *mockBlocklistRepo) CountEntriesGroupedBySource() (map[string]int64, error) {
	return nil, nil
}
func (m *mockBlocklistRepo) GetRecentSnapshots(sourceID string, limit int) ([]models.BlocklistSnapshot, error) {
	return nil, nil
}

func TestSeedIfEmpty_SeedsWhenNoSnapshot(t *testing.T) {
	repo := &mockBlocklistRepo{snapshotCount: 0}

	seeded, err := SeedIfEmpty(repo)
	if err != nil {
		t.Fatalf("SeedIfEmpty() error: %v", err)
	}
	if !seeded {
		t.Fatal("expected seeded=true when DB has no snapshot")
	}
	if repo.saveCalls != 1 {
		t.Fatalf("expected exactly 1 save call, got %d", repo.saveCalls)
	}

	// The synthetic source must be disabled and URL-less so the periodic
	// refresher never tries to fetch it.
	if repo.savedSource.ID != SourceID {
		t.Errorf("saved source ID = %q, want %q", repo.savedSource.ID, SourceID)
	}
	if repo.savedSource.Enabled {
		t.Error("bundled source must be Enabled=false")
	}
	if repo.savedSource.URL != "" {
		t.Errorf("bundled source URL must be empty, got %q", repo.savedSource.URL)
	}

	// Entries must match the parsed bundle exactly, all tagged to the source.
	want, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.savedEntries) != len(want) {
		t.Fatalf("saved %d entries, want %d", len(repo.savedEntries), len(want))
	}
	for i, e := range repo.savedEntries {
		if e.Domain != want[i].Domain {
			t.Errorf("entry[%d] domain = %q, want %q", i, e.Domain, want[i].Domain)
		}
		if e.SourceID != SourceID {
			t.Errorf("entry[%d] SourceID = %q, want %q", i, e.SourceID, SourceID)
		}
	}
}

func TestSeedIfEmpty_SkipsWhenSnapshotExists(t *testing.T) {
	repo := &mockBlocklistRepo{snapshotCount: 3} // fetched data already present

	seeded, err := SeedIfEmpty(repo)
	if err != nil {
		t.Fatalf("SeedIfEmpty() error: %v", err)
	}
	if seeded {
		t.Fatal("expected seeded=false when a snapshot already exists")
	}
	if repo.saveCalls != 0 {
		t.Errorf("expected no save calls when snapshot exists, got %d", repo.saveCalls)
	}
}

func TestSeedIfEmpty_IdempotentAcrossBoots(t *testing.T) {
	repo := &mockBlocklistRepo{snapshotCount: 0}

	// First boot: seeds.
	if seeded, err := SeedIfEmpty(repo); err != nil || !seeded {
		t.Fatalf("first SeedIfEmpty() = (%v, %v), want (true, nil)", seeded, err)
	}
	// Second boot: the seed created a snapshot, so it must skip and not
	// overwrite the previously seeded/fetched data.
	seeded, err := SeedIfEmpty(repo)
	if err != nil {
		t.Fatalf("second SeedIfEmpty() error: %v", err)
	}
	if seeded {
		t.Error("expected second boot to skip seeding")
	}
	if repo.saveCalls != 1 {
		t.Errorf("expected exactly 1 total save across two boots, got %d", repo.saveCalls)
	}
}

func TestSeedIfEmpty_PropagatesCountError(t *testing.T) {
	repo := &mockBlocklistRepo{countErr: errors.New("db down")}

	if _, err := SeedIfEmpty(repo); err == nil {
		t.Error("expected error to propagate from CountSnapshots")
	}
	if repo.saveCalls != 0 {
		t.Errorf("must not save when snapshot count is unknown, got %d save calls", repo.saveCalls)
	}
}
