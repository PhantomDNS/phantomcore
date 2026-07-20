// SPDX-License-Identifier: GPL-3.0-or-later
package bundle

import (
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

const (
	// SourceID is the synthetic source ID under which the embedded bundle is
	// persisted when seeded. It is disabled and has no URL so the periodic
	// refresh never attempts to fetch it.
	SourceID = "bundled-default"
	// SourceName is a human-readable name for the seeded source.
	SourceName = "Bundled Offline Default"
	// Category groups the seeded entries.
	Category = "default"
)

// SeedIfEmpty seeds the blocklist repository from the embedded offline bundle,
// but only when no blocklist snapshot exists yet. This makes filtering work
// from the first boot with no internet, while guaranteeing it never overwrites
// data that was already fetched from an online source: as soon as ANY snapshot
// exists (bundled or fetched, current or historical) seeding is skipped.
//
// It returns true when it actually seeded, false when it was skipped because a
// snapshot already existed.
func SeedIfEmpty(repo repositories.BlocklistRepository) (bool, error) {
	n, err := repo.CountSnapshots()
	if err != nil {
		return false, err
	}
	if n > 0 {
		// A snapshot already exists — either a prior bundled seed or real
		// fetched data. Never overwrite it.
		return false, nil
	}

	entries, err := Load()
	if err != nil {
		return false, err
	}

	checksum, err := Checksum()
	if err != nil {
		return false, err
	}

	now := time.Now()
	src := models.BlocklistSource{
		ID:        SourceID,
		Name:      SourceName,
		URL:       "", // embedded — nothing to fetch
		Format:    Format,
		Category:  Category,
		Enabled:   false, // keep the periodic refresher from touching it
		Priority:  0,
		CreatedAt: now,
	}

	modelEntries := make([]models.BlocklistEntry, len(entries))
	for i, e := range entries {
		modelEntries[i] = models.BlocklistEntry{
			Domain:    e.Domain,
			SourceID:  SourceID,
			Category:  Category,
			CreatedAt: now,
		}
	}

	if _, err := repo.SaveSnapshotWithEntries(src, checksum, modelEntries); err != nil {
		return false, err
	}
	return true, nil
}
