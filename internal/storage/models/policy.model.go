// SPDX-License-Identifier: GPL-3.0-or-later
package models

import "time"

type Policy struct {
	ID          string `gorm:"primaryKey;size:64"`
	Name        string `gorm:"not null"`
	Description string
	Category    string `gorm:"index"`
	Action      string `gorm:"not null"` // BLOCK, ALLOW, REDIRECT
	RedirectIP  string
	Domains     string `gorm:"type:text"` // JSON array stored as text
	Regexes     string `gorm:"type:text"` // JSON array stored as text
	Priority    int    `gorm:"default:0"`
	Enabled     bool   `gorm:"default:true"`

	// Optional schedule (I-038). All-empty means always active, so existing
	// rows keep their behaviour after AutoMigrate adds these nullable columns.
	ScheduleDays  string `gorm:"type:text"` // JSON array of day tokens; empty = every day
	ScheduleStart string // local "HH:MM" window start; empty = no window
	ScheduleEnd   string // local "HH:MM" window end
	Timezone      string // IANA timezone name; empty = UTC

	CreatedAt time.Time
	UpdatedAt time.Time
}
