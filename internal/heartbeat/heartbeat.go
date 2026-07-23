// SPDX-License-Identifier: GPL-3.0-or-later

// Package heartbeat provides opt-in, metadata-only status reporting for
// managed/fleet deployments.
//
// When a heartbeat URL is configured, a background reporter periodically POSTs
// an aggregate health snapshot to that URL. The payload contains ONLY
// operational metadata (uptime, QPS, blocked percentage, disk headroom,
// blocklist freshness, engine accepting-queries state) and never any DNS query
// contents or domain names, preserving the data-custody promise. The reporter
// is non-blocking and its failures are logged, never fatal.
package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/lopster568/phantomDNS/internal/dnsengine"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/metrics"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

const (
	// DefaultInterval is used when the configured interval is empty or invalid.
	DefaultInterval = 60 * time.Second
	// defaultHTTPTimeout bounds each POST so a slow collector never stalls the loop.
	defaultHTTPTimeout = 10 * time.Second
)

// MetricsSource exposes the rolling query metrics used for QPS and blocked%.
type MetricsSource interface {
	Aggregate() metrics.AggregatedMetrics
	Window() time.Duration
}

// EngineStatusSource exposes the DNS engine runtime status.
type EngineStatusSource interface {
	Status() dnsengine.Status
}

// BlocklistSource exposes blocklist source metadata for freshness reporting.
// Only source metadata is read; no domains or entries are ever touched.
type BlocklistSource interface {
	ListSources() ([]models.BlocklistSource, error)
}

// Status is the metadata-only health snapshot POSTed to the heartbeat URL.
//
// It deliberately carries NO domain names, client IPs, or query contents — only
// aggregate operational metadata suitable for fleet monitoring.
type Status struct {
	Status           string     `json:"status"` // "healthy" | "degraded"
	Healthy          bool       `json:"healthy"`
	Version          string     `json:"version,omitempty"`
	UptimeSeconds    int64      `json:"uptime_seconds"`
	AcceptingQueries bool       `json:"accepting_queries"`
	QPS              float64    `json:"qps"`
	BlockedPercent   float64    `json:"blocked_percent"`
	WindowQueries    uint64     `json:"window_queries"`
	WindowSeconds    int64      `json:"window_seconds"`
	DiskFreeBytes    uint64     `json:"disk_free_bytes"`
	DiskTotalBytes   uint64     `json:"disk_total_bytes"`
	BlocklistUpdated *time.Time `json:"blocklist_last_update,omitempty"`
	BlocklistAgeSec  *int64     `json:"blocklist_age_seconds,omitempty"`
	ReportedAt       time.Time  `json:"reported_at"`
}

// Config holds the heartbeat wiring. URL empty means disabled.
type Config struct {
	URL      string
	Interval string // duration string (e.g. "60s"); falls back to DefaultInterval
	DBPath   string
	Version  string // optional; resolved from build info when empty
}

// Reporter periodically assembles and POSTs a Status snapshot.
type Reporter struct {
	url       string
	interval  time.Duration
	version   string
	dbPath    string
	startedAt time.Time

	metrics   MetricsSource
	engine    EngineStatusSource
	blocklist BlocklistSource

	client    *http.Client
	now       func() time.Time
	diskUsage func(path string) (free, total uint64, err error)
}

// New builds a Reporter from cfg and the supplied data sources. It never
// returns an error; when cfg.URL is empty the returned reporter is disabled and
// Start becomes a no-op.
func New(cfg Config, m MetricsSource, e EngineStatusSource, bl BlocklistSource) *Reporter {
	interval := DefaultInterval
	if cfg.Interval != "" {
		if d, err := time.ParseDuration(cfg.Interval); err == nil && d > 0 {
			interval = d
		} else {
			logger.Log.Warnf("heartbeat: invalid interval %q, using %s", cfg.Interval, DefaultInterval)
		}
	}

	version := cfg.Version
	if version == "" {
		version = buildVersion()
	}

	return &Reporter{
		url:       cfg.URL,
		interval:  interval,
		version:   version,
		dbPath:    cfg.DBPath,
		startedAt: time.Now(),
		metrics:   m,
		engine:    e,
		blocklist: bl,
		client:    &http.Client{Timeout: defaultHTTPTimeout},
		now:       time.Now,
		diskUsage: diskUsage,
	}
}

// Enabled reports whether a heartbeat URL is configured.
func (r *Reporter) Enabled() bool {
	return r.url != ""
}

// Start launches the background reporter when enabled. It is a no-op (returning
// immediately, spawning nothing) when heartbeat is disabled. The loop runs
// until ctx is cancelled; reporting failures are logged, never fatal.
func (r *Reporter) Start(ctx context.Context) {
	if !r.Enabled() {
		logger.Log.Info("heartbeat: disabled (HEARTBEAT_URL not set)")
		return
	}

	logger.Log.Infof("heartbeat: enabled, reporting to %s every %s", r.url, r.interval)
	ticker := time.NewTicker(r.interval)
	go func() {
		defer ticker.Stop()
		r.loop(ctx, ticker.C)
	}()
}

// loop sends an initial snapshot, then one per tick, until ctx is cancelled.
// The tick channel is injectable so the cadence can be driven deterministically
// in tests.
func (r *Reporter) loop(ctx context.Context, tick <-chan time.Time) {
	// Send an initial snapshot immediately so fleet views populate on boot.
	if err := r.reportOnce(ctx); err != nil {
		logger.Log.Warnf("heartbeat: report failed: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if err := r.reportOnce(ctx); err != nil {
				logger.Log.Warnf("heartbeat: report failed: %v", err)
			}
		}
	}
}

// reportOnce assembles the current Status and POSTs it as JSON.
func (r *Reporter) reportOnce(ctx context.Context) error {
	status := r.Collect()

	body, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("post heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("heartbeat collector returned status %d", resp.StatusCode)
	}
	return nil
}

// Collect assembles the current metadata-only Status from the wired sources.
func (r *Reporter) Collect() Status {
	agg := r.metrics.Aggregate()
	window := r.metrics.Window()
	accepting := r.engine.Status().AcceptingQueries

	free, total, err := r.diskUsage(dbDir(r.dbPath))
	if err != nil {
		logger.Log.Warnf("heartbeat: disk usage for %q failed: %v", r.dbPath, err)
		free, total = 0, 0
	}

	return buildStatus(inputs{
		now:              r.now(),
		startedAt:        r.startedAt,
		version:          r.version,
		agg:              agg,
		window:           window,
		acceptingQueries: accepting,
		diskFree:         free,
		diskTotal:        total,
		blocklistUpdated: r.blocklistLastUpdate(),
	})
}

// blocklistLastUpdate returns the most recent blocklist source update time, or
// the zero time when unavailable. Only source metadata is read.
func (r *Reporter) blocklistLastUpdate() time.Time {
	if r.blocklist == nil {
		return time.Time{}
	}
	sources, err := r.blocklist.ListSources()
	if err != nil {
		logger.Log.Warnf("heartbeat: list blocklist sources failed: %v", err)
		return time.Time{}
	}
	var latest time.Time
	for _, s := range sources {
		if s.UpdatedAt.After(latest) {
			latest = s.UpdatedAt
		}
	}
	return latest
}

// inputs bundles the raw values buildStatus turns into a Status. Keeping this
// pure makes field mapping deterministic and unit-testable.
type inputs struct {
	now              time.Time
	startedAt        time.Time
	version          string
	agg              metrics.AggregatedMetrics
	window           time.Duration
	acceptingQueries bool
	diskFree         uint64
	diskTotal        uint64
	blocklistUpdated time.Time // zero => unknown
}

func buildStatus(in inputs) Status {
	windowSecs := in.window.Seconds()

	var qps float64
	if windowSecs > 0 {
		qps = float64(in.agg.Total) / windowSecs
	}

	var blockedPct float64
	if in.agg.Total > 0 {
		blockedPct = float64(in.agg.Blocked) / float64(in.agg.Total) * 100
	}

	statusStr := "healthy"
	if !in.acceptingQueries {
		statusStr = "degraded"
	}

	s := Status{
		Status:           statusStr,
		Healthy:          in.acceptingQueries,
		Version:          in.version,
		UptimeSeconds:    int64(in.now.Sub(in.startedAt).Seconds()),
		AcceptingQueries: in.acceptingQueries,
		QPS:              round2(qps),
		BlockedPercent:   round2(blockedPct),
		WindowQueries:    in.agg.Total,
		WindowSeconds:    int64(windowSecs),
		DiskFreeBytes:    in.diskFree,
		DiskTotalBytes:   in.diskTotal,
		ReportedAt:       in.now,
	}

	if !in.blocklistUpdated.IsZero() {
		updated := in.blocklistUpdated
		age := int64(in.now.Sub(updated).Seconds())
		s.BlocklistUpdated = &updated
		s.BlocklistAgeSec = &age
	}

	return s
}

// diskUsage returns free (available to unprivileged users) and total bytes for
// the filesystem backing path.
func diskUsage(path string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	return st.Bavail * bsize, st.Blocks * bsize, nil
}

// dbDir returns the directory holding the DB file so Statfs targets an existing
// path even before the DB file itself is created.
func dbDir(dbPath string) string {
	if dbPath == "" {
		return "."
	}
	dir := filepath.Dir(dbPath)
	if dir == "" {
		return "."
	}
	return dir
}

// buildVersion resolves a best-effort build version, falling back to "dev".
func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

// round2 rounds to two decimal places to keep the JSON payload tidy.
func round2(f float64) float64 {
	return math.Round(f*100) / 100
}
