// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"encoding/json"

	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// ToEnginePolicy converts a stored policy model into the in-memory policy
// used by the evaluation engine. Domains and Regexes are persisted as JSON
// text and decoded here. This is the single conversion used by both the
// dataplane (poll-based reload) and the control plane (immediate reload),
// so the two never drift.
func ToEnginePolicy(m models.Policy) policy.Policy {
	var domains, regexes, scheduleDays, clientCIDRs []string
	if m.Domains != "" {
		_ = json.Unmarshal([]byte(m.Domains), &domains)
	}
	if m.Regexes != "" {
		_ = json.Unmarshal([]byte(m.Regexes), &regexes)
	}
	if m.ScheduleDays != "" {
		_ = json.Unmarshal([]byte(m.ScheduleDays), &scheduleDays)
	}
	if m.ClientCIDRs != "" {
		_ = json.Unmarshal([]byte(m.ClientCIDRs), &clientCIDRs)
	}
	return policy.Policy{
		ID:           m.ID,
		Name:         m.Name,
		Description:  m.Description,
		Category:     m.Category,
		Action:       m.Action,
		Redirect:     m.RedirectIP,
		Enabled:      m.Enabled,
		Priority:     m.Priority,
		Domains:      domains,
		Regexes:      regexes,
		ScheduleDays: scheduleDays,
		StartTime:    m.ScheduleStart,
		EndTime:      m.ScheduleEnd,
		Timezone:     m.Timezone,
		ClientCIDRs:  clientCIDRs,
	}
}

type PolicyRepository interface {
	List() ([]models.Policy, error)
	GetByID(id string) (*models.Policy, error)
	Create(policy *models.Policy) error
	Update(policy *models.Policy) error
	Delete(id string) error
}

type PolicyRepo struct {
	db *gorm.DB
}

func NewPolicyRepo(db *gorm.DB) *PolicyRepo {
	return &PolicyRepo{db: db}
}

func (r *PolicyRepo) List() ([]models.Policy, error) {
	var policies []models.Policy
	err := r.db.Order("priority desc, id asc").Find(&policies).Error
	return policies, err
}

func (r *PolicyRepo) GetByID(id string) (*models.Policy, error) {
	var policy models.Policy
	err := r.db.First(&policy, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (r *PolicyRepo) Create(policy *models.Policy) error {
	return r.db.Create(policy).Error
}

func (r *PolicyRepo) Update(policy *models.Policy) error {
	return r.db.Save(policy).Error
}

func (r *PolicyRepo) Delete(id string) error {
	result := r.db.Delete(&models.Policy{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
