package repositories

import (
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// Interface (clean, mockable)
type QueryLogRepository interface {
	Save(query *models.DNSQuery) error
	ListRecent(limit int) ([]models.DNSQuery, error)
}

// Implementation
type GormQueryLogRepo struct {
	db *gorm.DB
}

func NewGormQueryLogRepo(db *gorm.DB) *GormQueryLogRepo {
	return &GormQueryLogRepo{db: db}
}

func (r *GormQueryLogRepo) Save(query *models.DNSQuery) error {
	query.Timestamp = time.Now()
	return r.db.Create(query).Error
}

func (r *GormQueryLogRepo) ListRecent(limit int) ([]models.DNSQuery, error) {
	var queries []models.DNSQuery
	err := r.db.Order("timestamp desc").Limit(limit).Find(&queries).Error
	return queries, err
}
