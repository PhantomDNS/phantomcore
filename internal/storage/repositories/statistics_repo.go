// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// Interface
type StatisticsRepository interface {
	Save(stat *models.Statistics) error
	ListRecent(limit int) ([]models.Statistics, error)
	IncrementCounter(action string) error
	SeedSingleton() error
}

// Implementation
type GormStatisticsRepo struct {
	db *gorm.DB
}

func NewGormStatisticsRepo(db *gorm.DB) *GormStatisticsRepo {
	return &GormStatisticsRepo{db: db}
}

func (r *GormStatisticsRepo) Save(stat *models.Statistics) error {
	stat.UpdatedAt = time.Now()
	logger.Log.Debug("Saving statistics record")
	logger.Log.Debug("stats", stat)
	return r.db.Save(stat).Error
}

func (r *GormStatisticsRepo) ListRecent(limit int) ([]models.Statistics, error) {
	var stats []models.Statistics
	err := r.db.Order("updated_at desc").Limit(limit).Find(&stats).Error
	return stats, err
}

// IncrementCounter increments the global counters (single-row statistics).
//
// Uses a single atomic UPDATE so concurrent callers (e.g. the query-log
// writer's worker pool) cannot race each other into lost updates, or, on
// cold boot, collide on duplicate INSERTs for id=1. The singleton row is
// expected to already exist (seeded via SeedSingleton at startup); if it
// doesn't, this call self-heals by seeding it and retrying once.
func (r *GormStatisticsRepo) IncrementCounter(action string) error {
	var bumpCol string
	switch action {
	case "allow":
		bumpCol = "allowed_queries"
	case "block":
		bumpCol = "blocked_queries"
	case "redirect":
		bumpCol = "redirected_queries"
	default:
		// treat unknown as total only
	}

	updates := map[string]interface{}{
		"total_queries": gorm.Expr("total_queries + 1"),
		"updated_at":    time.Now(),
	}
	if bumpCol != "" {
		updates[bumpCol] = gorm.Expr(bumpCol + " + 1")
	}

	res := r.db.Model(&models.Statistics{}).Where("id = ?", 1).Updates(updates)
	if res.Error != nil {
		logger.Log.Error("Failed to increment statistics: " + res.Error.Error())
		return res.Error
	}
	if res.RowsAffected == 0 {
		// Seed row is missing (first boot before SeedSingleton ran, or a
		// volume wipe between binary restarts). Recreate it idempotently
		// and retry the update once.
		if err := r.SeedSingleton(); err != nil {
			return err
		}
		res = r.db.Model(&models.Statistics{}).Where("id = ?", 1).Updates(updates)
		if res.Error != nil {
			logger.Log.Error("Failed to increment statistics after reseed: " + res.Error.Error())
			return res.Error
		}
	}

	return nil
}

// SeedSingleton inserts the statistics row with id=1 if it does not already
// exist. Safe to call many times (INSERT OR IGNORE), including concurrently.
func (r *GormStatisticsRepo) SeedSingleton() error {
	// Raw SQL keeps the insert idempotent across drivers without pulling
	// in clause.OnConflict, which behaves differently on SQLite.
	return r.db.Exec(
		"INSERT OR IGNORE INTO statistics (id, total_queries, blocked_queries, allowed_queries, redirected_queries, updated_at) VALUES (1, 0, 0, 0, 0, ?)",
		time.Now(),
	).Error
}
