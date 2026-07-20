// SPDX-License-Identifier: GPL-3.0-or-later
package blocklist

import (
	"context"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// fixedClock returns a deterministic wall clock for tests.
func fixedClock(t time.Time) Clock { return func() time.Time { return t } }

func snap(size int, created time.Time) *models.BlocklistSnapshot {
	return &models.BlocklistSnapshot{Size: size, CreatedAt: created}
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	th := HealthThresholds{StaleAfter: 7 * 24 * time.Hour, CollapseRatio: 0.5}
	src := models.BlocklistSource{ID: "s1", Name: "StevenBlack", Enabled: true}

	tests := []struct {
		name       string
		latest     *models.BlocklistSnapshot
		prev       *models.BlocklistSnapshot
		wantOK     bool
		wantReason HealthReason
	}{
		{
			name:       "dead: no snapshot ever produced",
			latest:     nil,
			prev:       nil,
			wantOK:     false,
			wantReason: ReasonNoData,
		},
		{
			name:       "dead: newest snapshot is empty",
			latest:     snap(0, now.Add(-time.Hour)),
			prev:       snap(1000, now.Add(-25*time.Hour)),
			wantOK:     false,
			wantReason: ReasonNoData,
		},
		{
			name:       "collapsed: count more than halved",
			latest:     snap(100, now.Add(-time.Hour)),
			prev:       snap(1000, now.Add(-25*time.Hour)),
			wantOK:     false,
			wantReason: ReasonCollapsed,
		},
		{
			name:       "stale: newest snapshot older than threshold",
			latest:     snap(1000, now.Add(-10*24*time.Hour)),
			prev:       nil,
			wantOK:     false,
			wantReason: ReasonStale,
		},
		{
			name:       "healthy: fresh, full, stable",
			latest:     snap(1000, now.Add(-time.Hour)),
			prev:       snap(1000, now.Add(-25*time.Hour)),
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "healthy: minor dip within tolerance",
			latest:     snap(800, now.Add(-time.Hour)),
			prev:       snap(1000, now.Add(-25*time.Hour)),
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "healthy: growth is never a collapse",
			latest:     snap(5000, now.Add(-time.Hour)),
			prev:       snap(1000, now.Add(-25*time.Hour)),
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "healthy: exactly at collapse floor is not flagged",
			latest:     snap(500, now.Add(-time.Hour)),
			prev:       snap(1000, now.Add(-25*time.Hour)),
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "collapse ignored without a baseline",
			latest:     snap(1, now.Add(-time.Hour)),
			prev:       nil,
			wantOK:     true,
			wantReason: ReasonOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluate(src, tc.latest, tc.prev, now, th)
			if got.OK != tc.wantOK {
				t.Fatalf("OK = %v, want %v (detail: %q)", got.OK, tc.wantOK, got.Detail)
			}
			if got.Reason != tc.wantReason {
				t.Fatalf("Reason = %q, want %q (detail: %q)", got.Reason, tc.wantReason, got.Detail)
			}
			if got.SourceID != src.ID || got.SourceName != src.Name {
				t.Fatalf("identity = %q/%q, want %q/%q", got.SourceID, got.SourceName, src.ID, src.Name)
			}
			if !got.CheckedAt.Equal(now) {
				t.Fatalf("CheckedAt = %v, want %v", got.CheckedAt, now)
			}
			if !got.OK && got.Detail == "" {
				t.Fatalf("expected a non-empty detail for unhealthy status")
			}
		})
	}
}

func TestEvaluate_DisabledThresholds(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	src := models.BlocklistSource{ID: "s1", Name: "src", Enabled: true}

	// Zero thresholds disable stale and collapse checks; only the dead check remains.
	th := HealthThresholds{}

	if st := evaluate(src, snap(1, now.Add(-100*24*time.Hour)), snap(1000, now), now, th); !st.OK {
		t.Fatalf("with checks disabled a populated source should be OK, got %q/%q", st.Reason, st.Detail)
	}
	if st := evaluate(src, nil, nil, now, th); st.OK {
		t.Fatalf("dead check must fire even with other thresholds disabled")
	}
}

// fakeData is an in-memory HealthDataSource for checker tests.
type fakeData struct {
	sources   []models.BlocklistSource
	snapshots map[string][]models.BlocklistSnapshot
	listErr   error
	snapErr   error
}

func (f *fakeData) ListSources() ([]models.BlocklistSource, error) {
	return f.sources, f.listErr
}

func (f *fakeData) GetRecentSnapshots(sourceID string, limit int) ([]models.BlocklistSnapshot, error) {
	if f.snapErr != nil {
		return nil, f.snapErr
	}
	all := f.snapshots[sourceID]
	if limit > 0 && limit < len(all) {
		all = all[:limit]
	}
	return all, nil
}

func TestHealthChecker_CheckOnce(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	th := HealthThresholds{StaleAfter: 7 * 24 * time.Hour, CollapseRatio: 0.5}

	data := &fakeData{
		sources: []models.BlocklistSource{
			{ID: "healthy", Name: "good", Enabled: true},
			{ID: "dead", Name: "bad", Enabled: true},
			{ID: "disabled", Name: "off", Enabled: false},
		},
		snapshots: map[string][]models.BlocklistSnapshot{
			// most-recent-first, as GetRecentSnapshots promises
			"healthy": {
				{Size: 1000, CreatedAt: now.Add(-time.Hour)},
				{Size: 1000, CreatedAt: now.Add(-25 * time.Hour)},
			},
			"dead": {},
		},
	}

	hc := NewHealthChecker(data, th, fixedClock(now))
	results := hc.CheckOnce()

	// disabled source is skipped: only 2 evaluated
	if len(results) != 2 {
		t.Fatalf("expected 2 evaluated sources, got %d", len(results))
	}

	unhealthy := hc.Unhealthy()
	if len(unhealthy) != 1 {
		t.Fatalf("expected 1 unhealthy source, got %d", len(unhealthy))
	}
	if unhealthy[0].SourceID != "dead" || unhealthy[0].Reason != ReasonNoData {
		t.Fatalf("unexpected unhealthy source: %+v", unhealthy[0])
	}
	if hc.Healthy() {
		t.Fatalf("Healthy() should be false while a source is unhealthy")
	}
	if len(hc.Statuses()) != 2 {
		t.Fatalf("expected 2 retained statuses, got %d", len(hc.Statuses()))
	}
}

func TestHealthChecker_CheckOnce_ListError(t *testing.T) {
	data := &fakeData{listErr: context.DeadlineExceeded}
	hc := NewHealthChecker(data, DefaultHealthThresholds(), fixedClock(time.Now()))
	if got := hc.CheckOnce(); got != nil {
		t.Fatalf("expected nil results on list error, got %+v", got)
	}
	if !hc.Healthy() {
		t.Fatalf("no evaluated sources should report healthy")
	}
}

func TestHealthChecker_SnapshotErrorSurfacesUnhealthy(t *testing.T) {
	now := time.Now()
	data := &fakeData{
		sources: []models.BlocklistSource{{ID: "s1", Name: "src", Enabled: true}},
		snapErr: context.DeadlineExceeded,
	}
	hc := NewHealthChecker(data, DefaultHealthThresholds(), fixedClock(now))
	results := hc.CheckOnce()
	if len(results) != 1 || results[0].OK {
		t.Fatalf("a source whose snapshots fail to load must surface as unhealthy, got %+v", results)
	}
	if results[0].Reason != ReasonNoData {
		t.Fatalf("expected %q, got %q", ReasonNoData, results[0].Reason)
	}
}

func TestHealthChecker_RunDisabledIntervalRunsOnce(t *testing.T) {
	now := time.Now()
	data := &fakeData{
		sources:   []models.BlocklistSource{{ID: "s1", Name: "src", Enabled: true}},
		snapshots: map[string][]models.BlocklistSnapshot{"s1": {{Size: 1000, CreatedAt: now}}},
	}
	hc := NewHealthChecker(data, DefaultHealthThresholds(), fixedClock(now))

	// A non-positive interval must perform a single check and return promptly.
	done := make(chan struct{})
	go func() {
		hc.Run(context.Background(), 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run with a disabled interval did not return")
	}
	if len(hc.Statuses()) != 1 {
		t.Fatalf("expected the single check to populate 1 status, got %d", len(hc.Statuses()))
	}
}
