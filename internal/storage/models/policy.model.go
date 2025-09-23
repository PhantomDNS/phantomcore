// SPDX-License-Identifier: GPL-3.0-or-later
package models

import "time"

type Policy struct {
	ID        uint   `gorm:"primaryKey"`
	Domain    string `gorm:"index;not null;"`
	Category  string `gorm:"index;"`
	Action    string `gorm:"not null;"` //allow, block, log
	CreatedAt time.Time
	UpdatedAt time.Time
}
