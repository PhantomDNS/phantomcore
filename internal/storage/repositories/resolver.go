// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// newResolverID returns a unique identifier for a resolver row.
func newResolverID() string {
	return uuid.New().String()
}

// ResolverRepository persists the editable upstream resolver set (I-003).
type ResolverRepository interface {
	// List returns all resolvers ordered by failover position (ascending).
	List() ([]models.Resolver, error)
	// Get returns a single resolver by ID.
	Get(id string) (*models.Resolver, error)
	// Create inserts a new resolver.
	Create(r *models.Resolver) error
	// Update persists changes to an existing resolver.
	Update(r *models.Resolver) error
	// Delete removes a resolver by ID.
	Delete(id string) error
	// Addresses returns resolver addresses ordered by failover position.
	// This is the ordered list applied to the dataplane upstream manager.
	Addresses() ([]string, error)
	// NextPosition returns the position to assign to a newly appended resolver.
	NextPosition() (int, error)
	// Count returns the number of persisted resolvers.
	Count() (int64, error)
	// SeedDefaults inserts the given addresses only if no resolvers exist yet.
	// Used to migrate the historical config-only resolver list into storage.
	SeedDefaults(addresses []string) error
}

type ResolverRepo struct {
	db *gorm.DB
}

func NewResolverRepo(db *gorm.DB) *ResolverRepo {
	return &ResolverRepo{db: db}
}

func (r *ResolverRepo) List() ([]models.Resolver, error) {
	var resolvers []models.Resolver
	err := r.db.Order("position asc, created_at asc").Find(&resolvers).Error
	return resolvers, err
}

func (r *ResolverRepo) Get(id string) (*models.Resolver, error) {
	var res models.Resolver
	if err := r.db.First(&res, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &res, nil
}

func (r *ResolverRepo) Create(res *models.Resolver) error {
	now := time.Now()
	if res.CreatedAt.IsZero() {
		res.CreatedAt = now
	}
	res.UpdatedAt = now
	return r.db.Create(res).Error
}

func (r *ResolverRepo) Update(res *models.Resolver) error {
	res.UpdatedAt = time.Now()
	result := r.db.Model(&models.Resolver{}).
		Where("id = ?", res.ID).
		Updates(map[string]interface{}{
			"name":       res.Name,
			"address":    res.Address,
			"protocol":   res.Protocol,
			"position":   res.Position,
			"updated_at": res.UpdatedAt,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *ResolverRepo) Delete(id string) error {
	result := r.db.Delete(&models.Resolver{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *ResolverRepo) Addresses() ([]string, error) {
	var addrs []string
	err := r.db.Model(&models.Resolver{}).
		Order("position asc, created_at asc").
		Pluck("address", &addrs).Error
	return addrs, err
}

func (r *ResolverRepo) NextPosition() (int, error) {
	var max struct {
		Value *int
	}
	err := r.db.Model(&models.Resolver{}).
		Select("MAX(position) as value").
		Scan(&max).Error
	if err != nil {
		return 0, err
	}
	if max.Value == nil {
		return 0, nil
	}
	return *max.Value + 1, nil
}

func (r *ResolverRepo) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.Resolver{}).Count(&count).Error
	return count, err
}

func (r *ResolverRepo) SeedDefaults(addresses []string) error {
	count, err := r.Count()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	now := time.Now()
	for i, addr := range addresses {
		res := &models.Resolver{
			ID:        newResolverID(),
			Name:      addr,
			Address:   addr,
			Protocol:  "udp",
			Position:  i,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := r.db.Create(res).Error; err != nil {
			return err
		}
	}
	return nil
}
