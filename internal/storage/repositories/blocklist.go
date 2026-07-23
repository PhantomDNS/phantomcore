// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"strings"
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// Interface (clean, mockable)
type BlocklistRepository interface {
	SaveSnapshotWithEntries(src models.BlocklistSource, checksum string, entries []models.BlocklistEntry) (models.BlocklistSnapshot, error)
	GetAll() ([]string, error)
	IsBlocked(domain string) (bool, error)
	ListSources() ([]models.BlocklistSource, error)
	GetSource(id string) (*models.BlocklistSource, error)
	CreateSource(src *models.BlocklistSource) error
	DeleteSource(id string) error
	CountEntriesBySource(sourceID string) (int64, error)
	CountEntriesGroupedBySource() (map[string]int64, error)
	GetRecentSnapshots(sourceID string, limit int) ([]models.BlocklistSnapshot, error)
}

// Implementation
type BlocklistRepo struct {
	db *gorm.DB
}

func NewBlocklistRepo(db *gorm.DB) *BlocklistRepo {
	return &BlocklistRepo{db: db}
}

func (r *BlocklistRepo) IsBlocked(domain string) (bool, error) {
	// Normalize domain (lowercase, remove trailing dot)
	d := strings.TrimSuffix(strings.ToLower(domain), ".")

	// Check exact match + parent domains (www.ads.google.com → ads.google.com → google.com)
	parts := strings.Split(d, ".")
	candidates := make([]string, 0, len(parts)-1)
	for i := 0; i < len(parts)-1; i++ {
		candidates = append(candidates, strings.Join(parts[i:], "."))
	}

	var count int64
	err := r.db.Model(&models.BlocklistEntry{}).
		Where("domain IN ?", candidates).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *BlocklistRepo) GetAll() ([]string, error) {
	var domains []string
	if err := r.db.Model(&models.BlocklistEntry{}).Pluck("domain", &domains).Error; err != nil {
		return nil, err
	}
	return domains, nil
}

func (r *BlocklistRepo) SaveSnapshotWithEntries(src models.BlocklistSource, checksum string, entries []models.BlocklistEntry) (models.BlocklistSnapshot, error) {
	tx := r.db.Begin()
	snapshot := models.BlocklistSnapshot{
		SourceID: src.ID, CreatedAt: time.Now(), Size: len(entries), Checksum: checksum,
	}
	if err := tx.Create(&snapshot).Error; err != nil {
		tx.Rollback()
		return snapshot, err
	}
	for i := range entries {
		entries[i].SnapshotID = snapshot.ID
		if err := tx.Create(&entries[i]).Error; err != nil {
			tx.Rollback()
			return snapshot, err
		}
	}
	// update source metadata
	src.UpdatedAt = time.Now()
	if err := tx.Save(&src).Error; err != nil {
		tx.Rollback()
		return snapshot, err
	}
	if err := tx.Commit().Error; err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (r *BlocklistRepo) ListSources() ([]models.BlocklistSource, error) {
	var sources []models.BlocklistSource
	err := r.db.Order("created_at desc").Find(&sources).Error
	return sources, err
}

func (r *BlocklistRepo) GetSource(id string) (*models.BlocklistSource, error) {
	var src models.BlocklistSource
	err := r.db.First(&src, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &src, nil
}

func (r *BlocklistRepo) CreateSource(src *models.BlocklistSource) error {
	return r.db.Create(src).Error
}

func (r *BlocklistRepo) DeleteSource(id string) error {
	tx := r.db.Begin()
	defer tx.Rollback() // no-op after commit

	if err := tx.Where("source_id = ?", id).Delete(&models.BlocklistEntry{}).Error; err != nil {
		return err
	}
	if err := tx.Where("source_id = ?", id).Delete(&models.BlocklistSnapshot{}).Error; err != nil {
		return err
	}
	result := tx.Delete(&models.BlocklistSource{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return tx.Commit().Error
}

func (r *BlocklistRepo) CountEntriesBySource(sourceID string) (int64, error) {
	var count int64
	err := r.db.Model(&models.BlocklistEntry{}).Where("source_id = ?", sourceID).Count(&count).Error
	return count, err
}

// GetRecentSnapshots returns up to limit snapshots for a source, most recent
// first. A non-positive limit returns all snapshots. Ordering is by creation
// time then ID so ties (snapshots written in the same instant) stay
// deterministic, which the health checker relies on for its collapse baseline.
func (r *BlocklistRepo) GetRecentSnapshots(sourceID string, limit int) ([]models.BlocklistSnapshot, error) {
	var snaps []models.BlocklistSnapshot
	q := r.db.Where("source_id = ?", sourceID).Order("created_at desc, id desc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	err := q.Find(&snaps).Error
	return snaps, err
}

// CountEntriesGroupedBySource returns domain counts keyed by source ID in a single query.
func (r *BlocklistRepo) CountEntriesGroupedBySource() (map[string]int64, error) {
	type result struct {
		SourceID string
		Count    int64
	}
	var results []result
	err := r.db.Model(&models.BlocklistEntry{}).
		Select("source_id, count(*) as count").
		Group("source_id").
		Find(&results).Error
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int64, len(results))
	for _, r := range results {
		counts[r.SourceID] = r.Count
	}
	return counts, nil
}
