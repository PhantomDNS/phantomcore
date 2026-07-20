// SPDX-License-Identifier: GPL-3.0-or-later

// Package diskhealth provides best-effort disk / SD-card health monitoring for
// unattended appliances. It tracks free space (and its growth trend) on the
// data/DB path, flags low free space or rapidly shrinking headroom, and — where
// trivially available — surfaces flash wear information.
//
// The core evaluation (evaluate) is a pure function over a sampled diskStat and
// a set of thresholds, which keeps the decision logic deterministic and easy to
// test without requiring a real low-disk condition. A Monitor wires that pure
// core to a periodic sampler and exposes the latest Status via a concurrency-safe
// accessor suitable for a health / heartbeat surface.
package diskhealth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
)

// ErrUnsupported is returned by the platform stat reader when free-space
// inspection is not available (e.g. non-unix builds). It is non-fatal: the
// Monitor logs and degrades gracefully.
var ErrUnsupported = errors.New("diskhealth: statfs unsupported on this platform")

// Reason codes for a non-OK status. They are stable strings so a health surface
// (or tests) can switch on them.
const (
	ReasonOK          = ""
	ReasonLowSpace    = "low-space"
	ReasonRapidGrowth = "rapid-growth"
)

// Sane defaults for unattended boxes. Overridable via environment.
const (
	DefaultInterval             = 5 * time.Minute
	DefaultMinFreePercent       = 10.0 // flag when free space dips below this
	DefaultGrowthPercentPerHour = 20.0 // flag when usage grows this fast (%-of-capacity/hour)
)

// Environment variable names.
const (
	EnvInterval       = "DISK_HEALTH_INTERVAL"
	EnvMinFreePercent = "DISK_MIN_FREE_PERCENT"
)

// diskStat is a single point-in-time sample of a filesystem.
type diskStat struct {
	Path       string
	TotalBytes uint64 // total capacity in bytes
	FreeBytes  uint64 // bytes available to unprivileged callers
	SampledAt  time.Time
}

// valid reports whether the sample carries usable capacity data.
func (d diskStat) valid() bool {
	return d.TotalBytes > 0 && !d.SampledAt.IsZero()
}

// freePercent returns free space as a percentage of total capacity (0 when the
// sample is empty).
func (d diskStat) freePercent() float64 {
	if d.TotalBytes == 0 {
		return 0
	}
	return float64(d.FreeBytes) / float64(d.TotalBytes) * 100
}

// usedBytes returns bytes consumed (never underflows).
func (d diskStat) usedBytes() uint64 {
	if d.FreeBytes >= d.TotalBytes {
		return 0
	}
	return d.TotalBytes - d.FreeBytes
}

// Thresholds configures when a sample is considered unhealthy.
type Thresholds struct {
	// MinFreePercent flags a status when free space falls below this percent.
	MinFreePercent float64
	// GrowthPercentPerHour flags a status when usage is growing faster than
	// this many percent-of-total-capacity per hour. Zero disables the check.
	GrowthPercentPerHour float64
}

// DefaultThresholds returns the built-in sane thresholds.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MinFreePercent:       DefaultMinFreePercent,
		GrowthPercentPerHour: DefaultGrowthPercentPerHour,
	}
}

// WearInfo is best-effort flash-wear data. It is nil when unavailable.
type WearInfo struct {
	Device      string // e.g. "mmcblk0"
	LifeUsedPct int    // estimated percent of rated write life consumed
	Source      string // where the estimate came from, e.g. "emmc-life_time"
}

// Status is the evaluated health of the monitored path. It is safe to copy and
// is the value returned by the health / heartbeat accessor.
type Status struct {
	OK          bool
	Reason      string // one of the Reason* codes; "" when OK
	Detail      string // human-readable elaboration
	Path        string
	TotalBytes  uint64
	FreeBytes   uint64
	FreePercent float64
	// GrowthPercentPerHour is the observed usage growth rate between the two
	// most recent samples, or 0 when not yet computable.
	GrowthPercentPerHour float64
	Wear                 *WearInfo // best-effort; nil when unavailable
	CheckedAt            time.Time
}

// growthRatePercentPerHour computes usage growth between prev and cur as a
// percentage of total capacity per hour. It returns 0 (not computable) when
// either sample is invalid, when no time elapsed, or when usage did not grow.
func growthRatePercentPerHour(prev, cur diskStat) float64 {
	if !prev.valid() || !cur.valid() || cur.TotalBytes == 0 {
		return 0
	}
	elapsed := cur.SampledAt.Sub(prev.SampledAt)
	if elapsed <= 0 {
		return 0
	}
	prevUsed := prev.usedBytes()
	curUsed := cur.usedBytes()
	if curUsed <= prevUsed {
		return 0
	}
	deltaPct := float64(curUsed-prevUsed) / float64(cur.TotalBytes) * 100
	return deltaPct / elapsed.Hours()
}

// evaluate is the pure core: given the current sample, an optional previous
// sample (for trend), and thresholds, it returns a Status. It performs no I/O
// and reads no clock, so it is fully deterministic.
//
// Precedence: low free space is reported ahead of rapid growth, since it is the
// more immediate failure condition.
func evaluate(prev, cur diskStat, th Thresholds) Status {
	freePct := cur.freePercent()
	growth := growthRatePercentPerHour(prev, cur)

	st := Status{
		OK:                   true,
		Reason:               ReasonOK,
		Path:                 cur.Path,
		TotalBytes:           cur.TotalBytes,
		FreeBytes:            cur.FreeBytes,
		FreePercent:          freePct,
		GrowthPercentPerHour: growth,
		CheckedAt:            cur.SampledAt,
	}

	switch {
	case th.MinFreePercent > 0 && freePct < th.MinFreePercent:
		st.OK = false
		st.Reason = ReasonLowSpace
		st.Detail = fmt.Sprintf("free space %.1f%% below minimum %.1f%%", freePct, th.MinFreePercent)
	case th.GrowthPercentPerHour > 0 && growth > th.GrowthPercentPerHour:
		st.OK = false
		st.Reason = ReasonRapidGrowth
		st.Detail = fmt.Sprintf("usage growing %.1f%%/hour above threshold %.1f%%/hour", growth, th.GrowthPercentPerHour)
	default:
		st.Detail = fmt.Sprintf("free space %.1f%% healthy", freePct)
	}

	return st
}

// LoadConfig resolves the monitor interval and thresholds from the environment,
// falling back to sane defaults. Invalid values are ignored (with a warning)
// rather than being treated as fatal.
func LoadConfig() (time.Duration, Thresholds) {
	interval := DefaultInterval
	if v := os.Getenv(EnvInterval); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		} else {
			logger.Log.Warnf("diskhealth: invalid %s=%q, using default %s", EnvInterval, v, DefaultInterval)
		}
	}

	th := DefaultThresholds()
	if v := os.Getenv(EnvMinFreePercent); v != "" {
		if p, err := strconv.ParseFloat(v, 64); err == nil && p > 0 && p < 100 {
			th.MinFreePercent = p
		} else {
			logger.Log.Warnf("diskhealth: invalid %s=%q, using default %.0f", EnvMinFreePercent, v, DefaultMinFreePercent)
		}
	}

	return interval, th
}

// Monitor periodically samples a path's free space and exposes the latest
// evaluated Status. It is safe for concurrent use.
type Monitor struct {
	dir        string
	interval   time.Duration
	thresholds Thresholds

	// injectable for testing; default to the platform implementations.
	readStat func(string) (diskStat, error)
	readWear func(string) *WearInfo

	mu      sync.RWMutex
	last    Status
	prev    diskStat
	hasPrev bool
}

// NewMonitor builds a Monitor for the directory containing dbPath. The directory
// (not the DB file itself) is what Statfs inspects, so the monitor keeps working
// even before the DB file exists.
func NewMonitor(dbPath string, interval time.Duration, th Thresholds) *Monitor {
	dir := filepath.Dir(dbPath)
	if dir == "" {
		dir = "."
	}
	return &Monitor{
		dir:        dir,
		interval:   interval,
		thresholds: th,
		readStat:   readDiskStat,
		readWear:   readWear,
		last: Status{
			OK:        true,
			Reason:    ReasonOK,
			Detail:    "not yet sampled",
			Path:      dir,
			CheckedAt: time.Time{},
		},
	}
}

// NewMonitorFromEnv is a convenience constructor that pulls interval and
// thresholds from the environment.
func NewMonitorFromEnv(dbPath string) *Monitor {
	interval, th := LoadConfig()
	return NewMonitor(dbPath, interval, th)
}

// Status returns the most recently evaluated health status. It is the accessor a
// health / heartbeat surface should call. Safe for concurrent use.
func (m *Monitor) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}

// sample takes one reading, evaluates it against the previous reading, attaches
// best-effort wear info, and stores the result. It returns the new Status.
func (m *Monitor) sample() Status {
	cur, err := m.readStat(m.dir)
	if err != nil {
		// Degrade gracefully: keep prior status, note the sampling failure.
		logger.Log.Warnf("diskhealth: failed to stat %s: %v", m.dir, err)
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.last
	}

	m.mu.Lock()
	prev := m.prev
	hadPrev := m.hasPrev
	m.mu.Unlock()

	var trendPrev diskStat
	if hadPrev {
		trendPrev = prev
	}

	st := evaluate(trendPrev, cur, m.thresholds)
	if w := m.readWear(m.dir); w != nil {
		st.Wear = w
	}

	m.mu.Lock()
	m.last = st
	m.prev = cur
	m.hasPrev = true
	m.mu.Unlock()

	if !st.OK {
		logger.Log.Warnf("diskhealth: %s unhealthy (%s): %s", m.dir, st.Reason, st.Detail)
	}
	return st
}

// Run samples immediately, then on every interval tick until ctx is cancelled.
// It is non-fatal and intended to be launched in its own goroutine.
func (m *Monitor) Run(ctx context.Context) {
	if m.interval <= 0 {
		m.interval = DefaultInterval
	}

	m.sample() // prime immediately so Status() is meaningful right away.

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sample()
		}
	}
}
