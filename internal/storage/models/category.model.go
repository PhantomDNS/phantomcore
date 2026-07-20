// SPDX-License-Identifier: GPL-3.0-or-later
package models

import "time"

type Category struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex;not null;"`   // e.g., "adult", "phishing"
	Description string `gorm:"type:text;"`              // optional description
	Type        string `gorm:"index;"`                  // "security" | "content"
	Enabled     bool   `gorm:"not null;default:false;"` // additive: categories are off until enabled
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
