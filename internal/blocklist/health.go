// SPDX-License-Identifier: GPL-3.0-or-later
package blocklist

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// Clock returns the current time. It is injectable so the health checker and its
// pure evaluation are fully deterministic under test.
type Clock func() time.Time

// HealthReason enumerates why a blocklist source is considered unhealthy.
// An empty reason means the source is healthy.
type HealthReason string

const (
	ReasonOK        HealthReason = ""
	ReasonNoData    HealthReason = "no_data"   // dead / unreachable: the source never produced usable entries
	ReasonCollapsed HealthReason = "collapsed" // domain count dropped sharply versus the previous snapshot
	ReasonStale     HealthReason = "stale"     // not refreshed within the staleness threshold
)

// HealthStatus is the outcome of evaluating a single blocklist source.
type HealthStatus struct {
	SourceID   string       `json:"source_id"`
	SourceName string       `json:"source_name"`
	OK         bool         `json:"ok"`
	Reason     HealthReason `json:"reason,omitempty"`
	Detail     string       `json:"detail,omitempty"`
	CheckedAt  time.Time    `json:"checked_at"`
}

// HealthThresholds tunes evaluate. A zero value for a field disables the
// corresponding check.
type HealthThresholds struct {
	// StaleAfter flags a source whose newest snapshot is older than this.
	StaleAfter time.Duration
	// CollapseRatio flags a source whose newest snapshot size fell below
	// previousSize * CollapseRatio. For example 0.5 means "flag if the domain
	// count more than halved versus the previous snapshot".
	CollapseRatio float64
}

// DefaultHealthThresholds returns conservative defaults: stale after a week,
// collapse when the count more than halves.
func DefaultHealthThresholds() HealthThresholds {
	return HealthThresholds{
		StaleAfter:    7 * 24 * time.Hour,
		CollapseRatio: 0.5,
	}
}

// evaluate is the pure health decision for a single source. It is deterministic:
// given the same inputs it always returns the same status.
//
//   - latest is the most recent snapshot for the source, or nil when the source
//     has never produced one.
//   - prev is the snapshot immediately before latest, used only as the baseline
//     for collapse detection; nil disables that check.
//   - now is the injected wall clock.
func evaluate(src models.BlocklistSource, latest, prev *models.BlocklistSnapshot, now time.Time, t HealthThresholds) HealthStatus {
	st := HealthStatus{
		SourceID:   src.ID,
		SourceName: src.Name,
		CheckedAt:  now,
		OK:         true,
	}

	// 1. Dead / unreachable: no snapshot has ever landed, or the newest one is
	//    empty. A dead or unreachable URL never populates usable entries, so this
	//    surfaces both.
	if latest == nil || latest.Size <= 0 {
		st.OK = false
		st.Reason = ReasonNoData
		if latest == nil {
			st.Detail = "no snapshot has ever been produced for this source"
		} else {
			st.Detail = "most recent snapshot contains zero domains"
		}
		return st
	}

	// 2. Collapsed: the newest domain count fell sharply versus the previous
	//    snapshot, which usually means the upstream returned a truncated or
	//    partial list.
	if t.CollapseRatio > 0 && prev != nil && prev.Size > 0 {
		floor := float64(prev.Size) * t.CollapseRatio
		if float64(latest.Size) < floor {
			drop := (1 - float64(latest.Size)/float64(prev.Size)) * 100
			st.OK = false
			st.Reason = ReasonCollapsed
			st.Detail = fmt.Sprintf("domain count fell %.0f%% (%d -> %d)", drop, prev.Size, latest.Size)
			return st
		}
	}

	// 3. Stale: the newest snapshot is older than the staleness threshold, so the
	//    source is no longer being refreshed.
	if t.StaleAfter > 0 {
		if age := now.Sub(latest.CreatedAt); age > t.StaleAfter {
			st.OK = false
			st.Reason = ReasonStale
			st.Detail = fmt.Sprintf("last updated %s ago (threshold %s)", age.Truncate(time.Second), t.StaleAfter)
			return st
		}
	}

	return st
}

// HealthDataSource is the read-only view of blocklist storage the checker needs.
// *repositories.BlocklistRepo satisfies it.
type HealthDataSource interface {
	ListSources() ([]models.BlocklistSource, error)
	GetRecentSnapshots(sourceID string, limit int) ([]models.BlocklistSnapshot, error)
}

// HealthChecker periodically evaluates every configured blocklist source and
// retains the latest per-source result so a status endpoint or heartbeat can
// report which sources are unhealthy.
type HealthChecker struct {
	data       HealthDataSource
	clock      Clock
	thresholds HealthThresholds

	mu       sync.RWMutex
	statuses map[string]HealthStatus
}

// NewHealthChecker builds a checker. A nil clock defaults to time.Now.
func NewHealthChecker(data HealthDataSource, thresholds HealthThresholds, clock Clock) *HealthChecker {
	if clock == nil {
		clock = time.Now
	}
	return &HealthChecker{
		data:       data,
		clock:      clock,
		thresholds: thresholds,
		statuses:   make(map[string]HealthStatus),
	}
}

// CheckOnce evaluates every enabled source once, refreshes the retained status
// map, logs a warning per unhealthy source, and returns the results. It is
// non-fatal: a storage error for one source is logged and that source is still
// evaluated (with no snapshot data, so it surfaces as unhealthy) rather than
// aborting the whole sweep.
func (h *HealthChecker) CheckOnce() []HealthStatus {
	sources, err := h.data.ListSources()
	if err != nil {
		logger.Log.Errorf("blocklist health: failed to list sources: %v", err)
		return nil
	}

	now := h.clock()
	results := make([]HealthStatus, 0, len(sources))
	fresh := make(map[string]HealthStatus, len(sources))

	for _, src := range sources {
		if !src.Enabled {
			continue
		}

		var latest, prev *models.BlocklistSnapshot
		snaps, err := h.data.GetRecentSnapshots(src.ID, 2)
		if err != nil {
			logger.Log.Errorf("blocklist health: failed to load snapshots for %s: %v", src.ID, err)
		} else {
			if len(snaps) > 0 {
				latest = &snaps[0]
			}
			if len(snaps) > 1 {
				prev = &snaps[1]
			}
		}

		st := evaluate(src, latest, prev, now, h.thresholds)
		if !st.OK {
			logger.Log.Warnf("blocklist source %q (%s) unhealthy: %s (%s)", st.SourceName, st.SourceID, st.Reason, st.Detail)
		}
		fresh[src.ID] = st
		results = append(results, st)
	}

	h.mu.Lock()
	h.statuses = fresh
	h.mu.Unlock()
	return results
}

// Run performs an immediate check and then re-checks on every tick of interval
// until ctx is cancelled. A non-positive interval disables periodic checking:
// Run performs a single check and returns, so BLOCKLIST_HEALTH_INTERVAL can turn
// the background monitor off.
func (h *HealthChecker) Run(ctx context.Context, interval time.Duration) {
	h.CheckOnce()
	if interval <= 0 {
		logger.Log.Info("blocklist health: periodic monitoring disabled (ran a single check)")
		return
	}

	logger.Log.Infof("blocklist health: monitoring every %s", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.CheckOnce()
		}
	}
}

// Statuses returns the most recent health status for every evaluated source.
func (h *HealthChecker) Statuses() []HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]HealthStatus, 0, len(h.statuses))
	for _, st := range h.statuses {
		out = append(out, st)
	}
	return out
}

// Unhealthy returns the sources currently flagged as unhealthy. It always
// returns a non-nil slice so it serialises cleanly from a status endpoint.
func (h *HealthChecker) Unhealthy() []HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]HealthStatus, 0)
	for _, st := range h.statuses {
		if !st.OK {
			out = append(out, st)
		}
	}
	return out
}

// Healthy reports whether every evaluated source is currently OK. A checker that
// has not run yet (no sources evaluated) is reported healthy.
func (h *HealthChecker) Healthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, st := range h.statuses {
		if !st.OK {
			return false
		}
	}
	return true
}
