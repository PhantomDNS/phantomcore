package repositories

import (
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

type Store struct {
	QueryLogs QueryLogRepository
	// Policies  PolicyRepository
	// Stats     StatsRepository
	// add more repos here...
}

func NewStore(db *gorm.DB) *Store {
	// Auto-migrate all models here (central place)
	_ = db.AutoMigrate(
		&models.DNSQuery{},
		// &models.Policy{},
		// &models.Statistic{},
		// &models.BlockedDomain{},
		// &models.SystemConfig{},
	)

	return &Store{
		QueryLogs: NewGormQueryLogRepo(db),
		// Policies:  NewGormPolicyRepo(db),
		// Stats:     NewGormStatsRepo(db),
	}
}
