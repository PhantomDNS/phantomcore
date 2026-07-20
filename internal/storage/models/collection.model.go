// SPDX-License-Identifier: GPL-3.0-or-later
package models

import "time"

// Collection is an app/service domain bundle (I-052): a small curated set of domains
// blocked as a single toggle (e.g. "TikTok", "Instagram"). It is modeled the same way
// as a Category — a named toggle backed by an aggregated blocklist source — but its
// domains are curated inline in the catalog rather than fetched from a remote feed.
type Collection struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex;not null;"`   // stable key, e.g. "tiktok"
	App         string `gorm:"index;"`                  // display name, e.g. "TikTok"
	Description string `gorm:"type:text;"`              // optional description
	Enabled     bool   `gorm:"not null;default:false;"` // additive: off until enabled
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
