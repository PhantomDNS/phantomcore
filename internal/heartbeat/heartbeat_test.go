// SPDX-License-Identifier: GPL-3.0-or-later
package heartbeat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/dnsengine"
	"github.com/lopster568/phantomDNS/internal/metrics"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// --- Fakes ---

type fakeMetrics struct {
	agg    metrics.AggregatedMetrics
	window time.Duration
	calls  int32
}

func (f *fakeMetrics) Aggregate() metrics.AggregatedMetrics {
	atomic.AddInt32(&f.calls, 1)
	return f.agg
}
func (f *fakeMetrics) Window() time.Duration { return f.window }

type fakeEngine struct{ status dnsengine.Status }

func (f fakeEngine) Status() dnsengine.Status { return f.status }

type fakeBlocklist struct {
	sources []models.BlocklistSource
	err     error
}

func (f fakeBlocklist) ListSources() ([]models.BlocklistSource, error) {
	return f.sources, f.err
}

func fixedDisk(free, total uint64) func(string) (uint64, uint64, error) {
	return func(string) (uint64, uint64, error) { return free, total, nil }
}

// --- buildStatus ---

func TestBuildStatus_Fields(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	in := inputs{
		now:              now,
		startedAt:        now.Add(-time.Hour),
		version:          "v1.2.3",
		agg:              metrics.AggregatedMetrics{Total: 600, Blocked: 150, Errors: 6},
		window:           5 * time.Minute,
		acceptingQueries: true,
		diskFree:         1000,
		diskTotal:        4000,
		blocklistUpdated: now.Add(-10 * time.Minute),
	}

	s := buildStatus(in)

	if s.Status != "healthy" || !s.Healthy {
		t.Errorf("status=%q healthy=%v, want healthy/true", s.Status, s.Healthy)
	}
	if s.Version != "v1.2.3" {
		t.Errorf("version=%q, want v1.2.3", s.Version)
	}
	if s.UptimeSeconds != 3600 {
		t.Errorf("uptime=%d, want 3600", s.UptimeSeconds)
	}
	if s.QPS != 2.0 { // 600 queries / 300s
		t.Errorf("qps=%v, want 2.0", s.QPS)
	}
	if s.BlockedPercent != 25.0 { // 150 / 600
		t.Errorf("blocked%%=%v, want 25.0", s.BlockedPercent)
	}
	if s.WindowQueries != 600 || s.WindowSeconds != 300 {
		t.Errorf("window queries=%d seconds=%d, want 600/300", s.WindowQueries, s.WindowSeconds)
	}
	if !s.AcceptingQueries {
		t.Error("expected AcceptingQueries true")
	}
	if s.DiskFreeBytes != 1000 || s.DiskTotalBytes != 4000 {
		t.Errorf("disk free=%d total=%d, want 1000/4000", s.DiskFreeBytes, s.DiskTotalBytes)
	}
	if s.BlocklistAgeSec == nil || *s.BlocklistAgeSec != 600 {
		t.Errorf("blocklist age=%v, want 600", s.BlocklistAgeSec)
	}
	if s.BlocklistUpdated == nil || !s.BlocklistUpdated.Equal(now.Add(-10*time.Minute)) {
		t.Errorf("blocklist updated=%v, want %v", s.BlocklistUpdated, now.Add(-10*time.Minute))
	}
	if !s.ReportedAt.Equal(now) {
		t.Errorf("reportedAt=%v, want %v", s.ReportedAt, now)
	}
}

func TestBuildStatus_DegradedAndZeroQueries(t *testing.T) {
	now := time.Now()
	s := buildStatus(inputs{
		now:              now,
		startedAt:        now,
		agg:              metrics.AggregatedMetrics{}, // no queries
		window:           5 * time.Minute,
		acceptingQueries: false, // not accepting -> degraded
	})

	if s.Status != "degraded" || s.Healthy {
		t.Errorf("status=%q healthy=%v, want degraded/false", s.Status, s.Healthy)
	}
	if s.QPS != 0 || s.BlockedPercent != 0 {
		t.Errorf("qps=%v blocked%%=%v, want 0/0 for empty window", s.QPS, s.BlockedPercent)
	}
	if s.BlocklistUpdated != nil || s.BlocklistAgeSec != nil {
		t.Error("expected nil blocklist fields when no update time is known")
	}
}

// --- Disabled reporter is a no-op ---

func TestReporter_DisabledIsNoop(t *testing.T) {
	fm := &fakeMetrics{window: 5 * time.Minute}
	r := New(Config{URL: ""}, fm, fakeEngine{}, fakeBlocklist{})

	if r.Enabled() {
		t.Fatal("reporter with empty URL should be disabled")
	}

	// Start must return immediately and spawn nothing, so the metrics source is
	// never queried.
	r.Start(context.Background())
	if got := atomic.LoadInt32(&fm.calls); got != 0 {
		t.Errorf("disabled reporter queried metrics %d times, want 0", got)
	}
}

// --- reportOnce POSTs valid, metadata-only JSON ---

func TestReporter_ReportOnce_PostsValidJSON(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotBody        []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotMethod = req.Method
		gotContentType = req.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(req.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	blUpdated := time.Now().Add(-5 * time.Minute)
	r := newTestReporter(srv.URL, &fakeMetrics{
		window: 5 * time.Minute,
		agg:    metrics.AggregatedMetrics{Total: 300, Blocked: 30},
	}, fakeEngine{status: dnsengine.Status{AcceptingQueries: true}},
		fakeBlocklist{sources: []models.BlocklistSource{{UpdatedAt: blUpdated}}})

	if err := r.reportOnce(context.Background()); err != nil {
		t.Fatalf("reportOnce: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method=%q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type=%q, want application/json", gotContentType)
	}

	var got Status
	if err := json.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("body is not valid JSON: %v (%s)", err, gotBody)
	}
	if got.Status != "healthy" || !got.AcceptingQueries {
		t.Errorf("payload status=%q accepting=%v, want healthy/true", got.Status, got.AcceptingQueries)
	}
	if got.QPS != 1.0 { // 300 / 300s
		t.Errorf("payload qps=%v, want 1.0", got.QPS)
	}
	if got.BlockedPercent != 10.0 { // 30 / 300
		t.Errorf("payload blocked%%=%v, want 10.0", got.BlockedPercent)
	}
	if got.DiskFreeBytes != 2048 {
		t.Errorf("payload disk free=%d, want 2048", got.DiskFreeBytes)
	}

	// Data-custody guard: the payload must carry no domain-level data.
	var generic map[string]any
	if err := json.Unmarshal(gotBody, &generic); err != nil {
		t.Fatalf("generic unmarshal: %v", err)
	}
	for k := range generic {
		if strings.Contains(strings.ToLower(k), "domain") || strings.Contains(strings.ToLower(k), "client") {
			t.Errorf("payload leaks per-record field %q; must be metadata-only", k)
		}
	}
}

// --- loop cadence is driven by the injected ticker ---

func TestReporter_Loop_ReportsPerTick(t *testing.T) {
	var count int32
	done := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
		done <- struct{}{}
	}))
	defer srv.Close()

	r := newTestReporter(srv.URL, &fakeMetrics{window: 5 * time.Minute},
		fakeEngine{status: dnsengine.Status{AcceptingQueries: true}}, fakeBlocklist{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tick := make(chan time.Time)
	go r.loop(ctx, tick)

	// Initial snapshot on start.
	<-done
	// Two ticks -> two more reports. Synchronising on `done` keeps the test
	// deterministic without sleeps.
	tick <- time.Now()
	<-done
	tick <- time.Now()
	<-done

	cancel()

	if got := atomic.LoadInt32(&count); got != 3 {
		t.Errorf("reports=%d, want 3 (initial + 2 ticks)", got)
	}
}

func TestBuildVersion_NonEmpty(t *testing.T) {
	if v := buildVersion(); v == "" {
		t.Error("buildVersion returned empty string")
	}
}

// newTestReporter builds a Reporter with injected clock and disk stat so tests
// stay deterministic and independent of the host filesystem.
func newTestReporter(url string, m MetricsSource, e EngineStatusSource, bl BlocklistSource) *Reporter {
	return &Reporter{
		url:       url,
		interval:  time.Hour,
		version:   "test",
		dbPath:    "/tmp/does-not-matter.db",
		startedAt: time.Now().Add(-time.Minute),
		metrics:   m,
		engine:    e,
		blocklist: bl,
		client:    &http.Client{Timeout: defaultHTTPTimeout},
		now:       time.Now,
		diskUsage: fixedDisk(2048, 8192),
	}
}
