// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// CategoryRepository persists the enable/disable state and metadata of catalog
// categories. The feed definitions themselves live in the code catalog; this repo only
// tracks which categories a user has turned on.
type CategoryRepository interface {
	List() ([]models.Category, error)
	GetByName(name string) (*models.Category, error)
	// EnsureExists inserts the category row if it is missing (seeding from the catalog),
	// leaving an existing row's Enabled state untouched.
	EnsureExists(cat *models.Category) error
	SetEnabled(name string, enabled bool) error
}

type CategoryRepo struct {
	db *gorm.DB
}

func NewCategoryRepo(db *gorm.DB) *CategoryRepo {
	return &CategoryRepo{db: db}
}

func (r *CategoryRepo) List() ([]models.Category, error) {
	var cats []models.Category
	err := r.db.Order("name asc").Find(&cats).Error
	return cats, err
}

func (r *CategoryRepo) GetByName(name string) (*models.Category, error) {
	var cat models.Category
	if err := r.db.First(&cat, "name = ?", name).Error; err != nil {
		return nil, err
	}
	return &cat, nil
}

// EnsureExists seeds the row on first use. FirstOrCreate matches on Name and, when the
// row already exists, loads it into cat without overwriting the persisted Enabled flag.
func (r *CategoryRepo) EnsureExists(cat *models.Category) error {
	return r.db.Where(models.Category{Name: cat.Name}).
		Attrs(models.Category{Description: cat.Description, Type: cat.Type}).
		FirstOrCreate(cat).Error
}

func (r *CategoryRepo) SetEnabled(name string, enabled bool) error {
	result := r.db.Model(&models.Category{}).Where("name = ?", name).Update("enabled", enabled)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
