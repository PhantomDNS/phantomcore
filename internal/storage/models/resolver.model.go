// SPDX-License-Identifier: GPL-3.0-or-later
package models

import "time"

// Resolver is a first-class, editable upstream DNS resolver.
//
// Prior to I-003 upstream resolvers were config-only (DataPlaneConfig.
// UpstreamResolvers). They are now persisted so they can be listed, added,
// edited, reordered and deleted at runtime via the control-plane API and
// applied live to the dataplane.
//
// Position defines failover order (ascending): the resolver with the lowest
// Position is tried first.
type Resolver struct {
	ID        string `gorm:"primaryKey"`
	Name      string `gorm:"not null"`
	Address   string `gorm:"not null"` // host:port
	Protocol  string `gorm:"not null"` // udp | tcp
	Position  int    `gorm:"not null"` // ordering for failover (ascending)
	CreatedAt time.Time
	UpdatedAt time.Time
}
