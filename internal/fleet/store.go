// SPDX-License-Identifier: GPL-3.0-or-later

// Package fleet implements a minimal, read-only MSP fleet-status aggregator.
//
// Boxes (deployed appliances) periodically POST aggregate heartbeat metadata —
// last-seen, QPS, blocked percentage, blocklist freshness and active alerts —
// and an operator can pull a consolidated per-site view. Only aggregate
// metadata is stored; query contents (domains, client IPs) are never accepted,
// keeping the feature custody-safe.
//
// The store is in-memory and keyed by site id. It is safe for concurrent use
// and takes an injectable clock so stale detection is deterministic in tests.
package fleet

import (
	"sort"
	"sync"
	"time"
)

// Site status values.
const (
	StatusUp   = "up"
	StatusDown = "down"
)

// Heartbeat is the aggregate metadata a box reports on each check-in. It
// deliberately carries no query contents — only counters and freshness markers.
type Heartbeat struct {
	SiteID             string     `json:"site_id" binding:"required"`
	Name               string     `json:"name,omitempty"`
	Version            string     `json:"version,omitempty"`
	QPS                float64    `json:"qps"`
	BlockedPercent     float64    `json:"blocked_percent"`
	BlocklistUpdatedAt *time.Time `json:"blocklist_updated_at,omitempty"`
	Alerts             []string   `json:"alerts,omitempty"`
}

// Site is the consolidated per-site view returned to operators.
type Site struct {
	SiteID              string     `json:"site_id"`
	Name                string     `json:"name,omitempty"`
	Version             string     `json:"version,omitempty"`
	Status              string     `json:"status"` // "up" or "down"
	LastSeen            time.Time  `json:"last_seen"`
	LastSeenAgeSeconds  int64      `json:"last_seen_age_seconds"`
	QPS                 float64    `json:"qps"`
	BlockedPercent      float64    `json:"blocked_percent"`
	BlocklistUpdatedAt  *time.Time `json:"blocklist_updated_at,omitempty"`
	BlocklistAgeSeconds *int64     `json:"blocklist_age_seconds,omitempty"`
	Alerts              []string   `json:"alerts,omitempty"`
}

// FleetView is the consolidated fleet snapshot.
type FleetView struct {
	GeneratedAt       time.Time `json:"generated_at"`
	StaleAfterSeconds int64     `json:"stale_after_seconds"`
	Total             int       `json:"total"`
	Up                int       `json:"up"`
	Down              int       `json:"down"`
	Sites             []Site    `json:"sites"`
}

type record struct {
	hb       Heartbeat
	lastSeen time.Time
}

// Store is an in-memory, concurrency-safe registry of site statuses keyed by
// site id.
type Store struct {
	mu         sync.RWMutex
	sites      map[string]record
	staleAfter time.Duration
	now        func() time.Time
}

// DefaultStaleAfter is the default no-heartbeat window before a site is
// considered down (3x a 30s heartbeat interval).
const DefaultStaleAfter = 90 * time.Second

// NewStore creates a Store. A site with no heartbeat within staleAfter is
// reported down. now supplies the clock and may be nil (defaults to time.Now);
// injecting it makes stale detection deterministic in tests.
func NewStore(staleAfter time.Duration, now func() time.Time) *Store {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	if now == nil {
		now = time.Now
	}
	return &Store{
		sites:      make(map[string]record),
		staleAfter: staleAfter,
		now:        now,
	}
}

// Record ingests a heartbeat, creating or updating the site keyed by SiteID.
// The last-seen time is stamped from the store clock, not the payload, so a box
// cannot backdate or forward-date itself.
func (s *Store) Record(hb Heartbeat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sites[hb.SiteID] = record{hb: hb, lastSeen: s.now()}
}

// Snapshot returns the consolidated fleet view. Sites are ordered by id for
// deterministic output; each is flagged up or down based on the store clock.
func (s *Store) Snapshot() FleetView {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now()
	sites := make([]Site, 0, len(s.sites))
	up, down := 0, 0

	for _, r := range s.sites {
		age := now.Sub(r.lastSeen)
		status := StatusUp
		if age > s.staleAfter {
			status = StatusDown
			down++
		} else {
			up++
		}

		sv := Site{
			SiteID:             r.hb.SiteID,
			Name:               r.hb.Name,
			Version:            r.hb.Version,
			Status:             status,
			LastSeen:           r.lastSeen,
			LastSeenAgeSeconds: int64(age.Seconds()),
			QPS:                r.hb.QPS,
			BlockedPercent:     r.hb.BlockedPercent,
			Alerts:             r.hb.Alerts,
		}
		if r.hb.BlocklistUpdatedAt != nil {
			t := *r.hb.BlocklistUpdatedAt
			sv.BlocklistUpdatedAt = &t
			secs := int64(now.Sub(t).Seconds())
			sv.BlocklistAgeSeconds = &secs
		}
		sites = append(sites, sv)
	}

	sort.Slice(sites, func(i, j int) bool { return sites[i].SiteID < sites[j].SiteID })

	return FleetView{
		GeneratedAt:       now,
		StaleAfterSeconds: int64(s.staleAfter.Seconds()),
		Total:             len(sites),
		Up:                up,
		Down:              down,
		Sites:             sites,
	}
}
