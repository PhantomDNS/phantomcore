// SPDX-License-Identifier: GPL-3.0-or-later

package diskhealth

import (
	"errors"
	"testing"
	"time"
)

const gib = uint64(1) << 30

// base is a fixed reference time so growth math is fully deterministic.
var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func mkStat(totalGiB, freeGiB uint64, at time.Time) diskStat {
	return diskStat{
		Path:       "/data",
		TotalBytes: totalGiB * gib,
		FreeBytes:  freeGiB * gib,
		SampledAt:  at,
	}
}

func TestEvaluate(t *testing.T) {
	th := Thresholds{MinFreePercent: 10, GrowthPercentPerHour: 20}

	tests := []struct {
		name       string
		prev       diskStat
		cur        diskStat
		th         Thresholds
		wantOK     bool
		wantReason string
	}{
		{
			name:       "healthy: plenty free, no prev",
			cur:        mkStat(100, 80, base),
			th:         th,
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "healthy: exactly at min free is OK",
			cur:        mkStat(100, 10, base), // 10% free, min is 10% -> not below
			th:         th,
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "low space: below min, no prev",
			cur:        mkStat(100, 5, base), // 5% free
			th:         th,
			wantOK:     false,
			wantReason: ReasonLowSpace,
		},
		{
			name:       "low space: just under min",
			cur:        mkStat(1000, 99, base), // 9.9% free
			th:         th,
			wantOK:     false,
			wantReason: ReasonLowSpace,
		},
		{
			name:       "low space: totally full",
			cur:        mkStat(64, 0, base),
			th:         th,
			wantOK:     false,
			wantReason: ReasonLowSpace,
		},
		{
			name:       "rapid growth: usage up 30%/hour, still above min free",
			prev:       mkStat(100, 70, base),
			cur:        mkStat(100, 40, base.Add(time.Hour)), // used 30->60, +30% in 1h
			th:         th,
			wantOK:     false,
			wantReason: ReasonRapidGrowth,
		},
		{
			name:       "slow growth: 10%/hour under 20 threshold is OK",
			prev:       mkStat(100, 60, base),
			cur:        mkStat(100, 50, base.Add(time.Hour)), // +10% in 1h
			th:         th,
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "growth over shorter window: +5% in 15min -> 20%/hour, at threshold not over",
			prev:       mkStat(100, 55, base),
			cur:        mkStat(100, 50, base.Add(15*time.Minute)), // +5% in .25h = 20%/h, not > 20
			th:         th,
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "growth over shorter window: +6% in 15min -> 24%/hour flagged",
			prev:       mkStat(1000, 550, base),
			cur:        mkStat(1000, 490, base.Add(15*time.Minute)), // +6% in .25h = 24%/h
			th:         th,
			wantOK:     false,
			wantReason: ReasonRapidGrowth,
		},
		{
			name:       "low space wins over rapid growth (precedence)",
			prev:       mkStat(100, 40, base),
			cur:        mkStat(100, 5, base.Add(time.Hour)), // 5% free AND +35%/h growth
			th:         th,
			wantOK:     false,
			wantReason: ReasonLowSpace,
		},
		{
			name:       "usage shrinking is never rapid-growth",
			prev:       mkStat(100, 20, base),
			cur:        mkStat(100, 80, base.Add(time.Hour)), // freed up space
			th:         th,
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "growth check disabled when threshold is zero",
			prev:       mkStat(100, 90, base),
			cur:        mkStat(100, 30, base.Add(time.Hour)), // +60%/h but check off
			th:         Thresholds{MinFreePercent: 10, GrowthPercentPerHour: 0},
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "zero elapsed time yields no growth flag",
			prev:       mkStat(100, 80, base),
			cur:        mkStat(100, 20, base), // same instant
			th:         th,
			wantOK:     true,
			wantReason: ReasonOK,
		},
		{
			name:       "min-free check disabled when threshold is zero, growth still evaluated",
			prev:       mkStat(100, 40, base),
			cur:        mkStat(100, 2, base.Add(time.Hour)), // 2% free but min disabled; +38%/h
			th:         Thresholds{MinFreePercent: 0, GrowthPercentPerHour: 20},
			wantOK:     false,
			wantReason: ReasonRapidGrowth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluate(tt.prev, tt.cur, tt.th)
			if got.OK != tt.wantOK {
				t.Errorf("OK = %v, want %v (detail: %s)", got.OK, tt.wantOK, got.Detail)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q (detail: %s)", got.Reason, tt.wantReason, got.Detail)
			}
			// Status must always echo the current sample's capacity data.
			if got.TotalBytes != tt.cur.TotalBytes || got.FreeBytes != tt.cur.FreeBytes {
				t.Errorf("capacity not echoed: got total=%d free=%d, want total=%d free=%d",
					got.TotalBytes, got.FreeBytes, tt.cur.TotalBytes, tt.cur.FreeBytes)
			}
		})
	}
}

func TestFreePercent(t *testing.T) {
	if got := mkStat(100, 25, base).freePercent(); got != 25 {
		t.Errorf("freePercent = %v, want 25", got)
	}
	// Empty sample must not divide by zero.
	if got := (diskStat{}).freePercent(); got != 0 {
		t.Errorf("empty freePercent = %v, want 0", got)
	}
}

func TestUsedBytesNoUnderflow(t *testing.T) {
	// Free exceeding total (shouldn't happen, but must not underflow).
	s := diskStat{TotalBytes: 10, FreeBytes: 20}
	if got := s.usedBytes(); got != 0 {
		t.Errorf("usedBytes underflow guard failed: got %d, want 0", got)
	}
}

func TestGrowthRateHelper(t *testing.T) {
	// Invalid prev -> not computable.
	if r := growthRatePercentPerHour(diskStat{}, mkStat(100, 50, base)); r != 0 {
		t.Errorf("growth with invalid prev = %v, want 0", r)
	}
	// Clean 20%/hour.
	r := growthRatePercentPerHour(mkStat(100, 70, base), mkStat(100, 50, base.Add(time.Hour)))
	if r != 20 {
		t.Errorf("growth = %v, want 20", r)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv(EnvInterval, "")
	t.Setenv(EnvMinFreePercent, "")
	interval, th := LoadConfig()
	if interval != DefaultInterval {
		t.Errorf("interval = %v, want %v", interval, DefaultInterval)
	}
	if th.MinFreePercent != DefaultMinFreePercent {
		t.Errorf("min free = %v, want %v", th.MinFreePercent, DefaultMinFreePercent)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv(EnvInterval, "30s")
	t.Setenv(EnvMinFreePercent, "15")
	interval, th := LoadConfig()
	if interval != 30*time.Second {
		t.Errorf("interval = %v, want 30s", interval)
	}
	if th.MinFreePercent != 15 {
		t.Errorf("min free = %v, want 15", th.MinFreePercent)
	}
}

func TestLoadConfigInvalidFallsBack(t *testing.T) {
	t.Setenv(EnvInterval, "not-a-duration")
	t.Setenv(EnvMinFreePercent, "500") // out of (0,100)
	interval, th := LoadConfig()
	if interval != DefaultInterval {
		t.Errorf("invalid interval should fall back, got %v", interval)
	}
	if th.MinFreePercent != DefaultMinFreePercent {
		t.Errorf("invalid min free should fall back, got %v", th.MinFreePercent)
	}
}

func TestMonitorSample(t *testing.T) {
	m := NewMonitor("/data/phantomdns.db", time.Minute, Thresholds{MinFreePercent: 10, GrowthPercentPerHour: 20})

	// Before sampling, Status is the neutral placeholder.
	if !m.Status().OK {
		t.Fatalf("initial status should be OK placeholder")
	}

	// Inject a deterministic low-space reading.
	m.readStat = func(string) (diskStat, error) {
		return mkStat(100, 3, base), nil
	}
	m.readWear = func(string) *WearInfo {
		return &WearInfo{Device: "mmcblk0", LifeUsedPct: 40, Source: "test"}
	}

	st := m.sample()
	if st.OK || st.Reason != ReasonLowSpace {
		t.Fatalf("expected low-space, got OK=%v reason=%q", st.OK, st.Reason)
	}
	if st.Wear == nil || st.Wear.LifeUsedPct != 40 {
		t.Fatalf("wear info not attached: %+v", st.Wear)
	}
	// Accessor must reflect the latest sample.
	if got := m.Status(); got.Reason != ReasonLowSpace {
		t.Fatalf("Status() accessor stale: %q", got.Reason)
	}
}

func TestMonitorSampleErrorKeepsPriorStatus(t *testing.T) {
	m := NewMonitor("/data/phantomdns.db", time.Minute, DefaultThresholds())

	// First: a healthy reading.
	m.readWear = func(string) *WearInfo { return nil }
	m.readStat = func(string) (diskStat, error) { return mkStat(100, 90, base), nil }
	healthy := m.sample()
	if !healthy.OK {
		t.Fatalf("expected healthy, got %q", healthy.Reason)
	}

	// Then: sampler errors -> prior status is retained, not overwritten.
	m.readStat = func(string) (diskStat, error) { return diskStat{}, errors.New("boom") }
	after := m.sample()
	if !after.OK {
		t.Fatalf("errored sample should retain healthy status, got %q", after.Reason)
	}
}

func TestMonitorGrowthAcrossSamples(t *testing.T) {
	m := NewMonitor("/data/phantomdns.db", time.Minute, Thresholds{MinFreePercent: 5, GrowthPercentPerHour: 20})
	m.readWear = func(string) *WearInfo { return nil }

	// First sample establishes a baseline (no prev -> can't flag growth).
	m.readStat = func(string) (diskStat, error) { return mkStat(100, 70, base), nil }
	if first := m.sample(); !first.OK {
		t.Fatalf("first sample should be OK, got %q", first.Reason)
	}

	// Second sample an hour later with usage up 30% -> rapid growth.
	m.readStat = func(string) (diskStat, error) { return mkStat(100, 40, base.Add(time.Hour)), nil }
	second := m.sample()
	if second.OK || second.Reason != ReasonRapidGrowth {
		t.Fatalf("expected rapid-growth on second sample, got OK=%v reason=%q", second.OK, second.Reason)
	}
	if second.GrowthPercentPerHour != 30 {
		t.Errorf("growth rate = %v, want 30", second.GrowthPercentPerHour)
	}
}
