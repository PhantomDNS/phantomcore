// SPDX-License-Identifier: GPL-3.0-or-later
package models

import "time"

type DNSQuery struct {
	ID              uint      `gorm:"primaryKey"`
	Domain          string    `gorm:"index;not null;"`
	ClientIP        string    `gorm:"index;not null;"`
	Action          string    `gorm:"index;not null;"` // allow, block, redirect, flagged
	Timestamp       time.Time `gorm:"index;"`
	IsSuspicious    bool      `gorm:"default:false"`
	ThreatScore     float64   `gorm:"default:0"`
	DetectionMethod string    `gorm:"default:''"`
	ThreatReason    string    `gorm:"default:''"`
	BlockReason     string    `gorm:"default:''"` // why the query was blocked/redirected: "blocklist", a policy ID, "redirect:<policyID>", a threat method, or "" for allow
}
