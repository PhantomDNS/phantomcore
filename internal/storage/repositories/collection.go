// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// CollectionRepository persists the enable/disable state of app/service collections
// (I-052). The curated domain bundles live in the code catalog; this repo only tracks
// which collections a user has turned on.
type CollectionRepository interface {
	List() ([]models.Collection, error)
	GetByName(name string) (*models.Collection, error)
	EnsureExists(col *models.Collection) error
	SetEnabled(name string, enabled bool) error
}

type CollectionRepo struct {
	db *gorm.DB
}

func NewCollectionRepo(db *gorm.DB) *CollectionRepo {
	return &CollectionRepo{db: db}
}

func (r *CollectionRepo) List() ([]models.Collection, error) {
	var cols []models.Collection
	err := r.db.Order("name asc").Find(&cols).Error
	return cols, err
}

func (r *CollectionRepo) GetByName(name string) (*models.Collection, error) {
	var col models.Collection
	if err := r.db.First(&col, "name = ?", name).Error; err != nil {
		return nil, err
	}
	return &col, nil
}

func (r *CollectionRepo) EnsureExists(col *models.Collection) error {
	return r.db.Where(models.Collection{Name: col.Name}).
		Attrs(models.Collection{App: col.App, Description: col.Description}).
		FirstOrCreate(col).Error
}

func (r *CollectionRepo) SetEnabled(name string, enabled bool) error {
	result := r.db.Model(&models.Collection{}).Where("name = ?", name).Update("enabled", enabled)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
