// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"sync"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/metrics"
	"github.com/lopster568/phantomDNS/internal/report"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

// recordingQueryLog captures every saved row, optionally blocking each Save
// call on a gate channel so tests can hold workers busy on demand. When
// started is non-nil, the *first* Save call signals on it right before
// blocking on gate, so a test can deterministically wait until a worker is
// actually occupied instead of racing worker scheduling against filling the
// queue buffer. Only the first call signals (via startedOnce): once gate is
// closed, later Save calls return immediately, and re-signaling on an
// already-drained/unread "started" would deadlock the worker permanently.
type recordingQueryLog struct {
	mu          sync.Mutex
	saved       []*models.DNSQuery
	gate        chan struct{} // if non-nil, each Save blocks until this is closed
	started     chan struct{} // if non-nil, the first Save sends here just before blocking on gate
	startedOnce sync.Once
}

func (r *recordingQueryLog) Save(q *models.DNSQuery) error {
	if r.gate != nil {
		if r.started != nil {
			r.startedOnce.Do(func() { r.started <- struct{}{} })
		}
		<-r.gate
	}
	r.mu.Lock()
	r.saved = append(r.saved, q)
	r.mu.Unlock()
	return nil
}

func (r *recordingQueryLog) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.saved)
}

func (r *recordingQueryLog) ListRecent(limit int) ([]models.DNSQuery, error) { return nil, nil }

func (r *recordingQueryLog) List(filter repositories.QueryLogFilter) ([]models.DNSQuery, int64, error) {
	return nil, 0, nil
}

func (r *recordingQueryLog) TopClients(w repositories.AnalyticsWindow) ([]repositories.ClientActivity, error) {
	return nil, nil
}

func (r *recordingQueryLog) TopBlockedDomains(w repositories.AnalyticsWindow) ([]repositories.DomainCount, error) {
	return nil, nil
}

func (r *recordingQueryLog) CategoryBreakdown(w repositories.AnalyticsWindow) ([]repositories.CategoryCount, error) {
	return nil, nil
}

func (r *recordingQueryLog) ClientTimeline(clientIP string, w repositories.AnalyticsWindow) ([]repositories.TimeBucket, error) {
	return nil, nil
}

func (r *recordingQueryLog) CategoryHourHeatmap(w repositories.AnalyticsWindow) ([]repositories.HeatmapCell, error) {
	return nil, nil
}

func (r *recordingQueryLog) GatherWindowStats(w repositories.AnalyticsWindow) (repositories.WindowStats, error) {
	return repositories.WindowStats{}, nil
}

func (r *recordingQueryLog) AnomalyDigestBetween(current, prior repositories.AnalyticsWindow, cfg repositories.AnomalyThresholds) (repositories.AnomalyDigest, error) {
	return repositories.AnomalyDigest{}, nil
}

func (r *recordingQueryLog) Aggregate(from, to time.Time, topN int) (report.Aggregates, error) {
	return report.Aggregates{}, nil
}

// recordingStats counts IncrementCounter calls per action.
type recordingStats struct {
	mu     sync.Mutex
	counts map[string]int
}

func newRecordingStats() *recordingStats {
	return &recordingStats{counts: map[string]int{}}
}

func (s *recordingStats) Save(stat *models.Statistics) error { return nil }

func (s *recordingStats) ListRecent(limit int) ([]models.Statistics, error) { return nil, nil }

func (s *recordingStats) IncrementCounter(action string) error {
	s.mu.Lock()
	s.counts[action]++
	s.mu.Unlock()
	return nil
}

func (s *recordingStats) get(action string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[action]
}

// waitFor polls cond until it returns true or the timeout elapses, failing
// the test on timeout. Used instead of a fixed sleep so the test is not
// flaky under load while still bounded in wall-clock time.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}

// TestQueryLogWriter_ProcessesQueued verifies every submitted row is
// eventually persisted and its paired statistics counter incremented.
func TestQueryLogWriter_ProcessesQueued(t *testing.T) {
	ql := &recordingQueryLog{}
	st := newRecordingStats()
	w := newQueryLogWriter(ql, st, metrics.NewQueryMetrics(), 0, 0)
	defer w.Close()

	const n = 50
	for i := 0; i < n; i++ {
		w.Submit(&models.DNSQuery{Domain: "example.com"}, "allow")
	}

	waitFor(t, 2*time.Second, func() bool { return ql.count() == n })

	if got := st.get("allow"); got != n {
		t.Errorf("stats count for %q = %d, want %d", "allow", got, n)
	}
	if d := w.Dropped(); d != 0 {
		t.Errorf("Dropped() = %d, want 0", d)
	}
}

// TestQueryLogWriter_DropsWhenSaturated verifies Submit never blocks the
// caller and drops (with a counted, metrics-visible drop) once the buffer
// and worker are saturated, rather than piling up unbounded work.
func TestQueryLogWriter_DropsWhenSaturated(t *testing.T) {
	const bufSize = 2
	const workers = 1

	gate := make(chan struct{})             // Save blocks here until closed
	started := make(chan struct{}, workers) // Save signals here just before blocking
	ql := &recordingQueryLog{gate: gate, started: started}
	st := newRecordingStats()
	qm := metrics.NewQueryMetrics()

	w := newQueryLogWriter(ql, st, qm, bufSize, workers)
	defer w.Close()

	// Submit one entry and wait for the (single) worker to actually pick it
	// up and block in Save. After this, the queue channel is empty again but
	// the worker is occupied, so it is deterministic that the next bufSize
	// Submits fill the channel exactly.
	w.Submit(&models.DNSQuery{Domain: "occupy-worker"}, "allow")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the worker to become occupied")
	}

	// Fill the buffer exactly to capacity; each send must return immediately.
	fillDone := make(chan struct{})
	go func() {
		for i := 0; i < bufSize; i++ {
			w.Submit(&models.DNSQuery{Domain: "fill.example"}, "allow")
		}
		close(fillDone)
	}()
	select {
	case <-fillDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out filling the writer buffer; Submit should never block")
	}

	// The worker is occupied and the buffer is now full. The next Submit
	// must be dropped, not queued, and must return immediately rather than
	// blocking on the saturated channel.
	submitDone := make(chan struct{})
	go func() {
		w.Submit(&models.DNSQuery{Domain: "overflow.example"}, "allow")
		close(submitDone)
	}()
	select {
	case <-submitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked on a saturated writer instead of dropping")
	}

	if d := w.Dropped(); d != 1 {
		t.Errorf("Dropped() = %d, want 1", d)
	}
	if agg := qm.Aggregate(); agg.QueryLogDropped != 1 {
		t.Errorf("metrics QueryLogDropped = %d, want 1", agg.QueryLogDropped)
	}

	// Release the worker and let everything queued actually persist:
	// the one occupying the worker plus the bufSize that filled the channel.
	close(gate)
	waitFor(t, 2*time.Second, func() bool { return ql.count() == 1+bufSize })
}

// TestQueryLogWriter_DrainsOnShutdown verifies Close waits for every already
// -submitted row to finish persisting before returning (graceful drain).
func TestQueryLogWriter_DrainsOnShutdown(t *testing.T) {
	ql := &recordingQueryLog{}
	st := newRecordingStats()
	w := newQueryLogWriter(ql, st, metrics.NewQueryMetrics(), 64, 2)

	const n = 30
	for i := 0; i < n; i++ {
		w.Submit(&models.DNSQuery{Domain: "example.com"}, "allow")
	}

	w.Close() // must not return until all n rows are persisted

	if got := ql.count(); got != n {
		t.Errorf("after Close: persisted %d rows, want %d", got, n)
	}

	// Close must be idempotent.
	w.Close()
}

// TestQueryLogWriter_NilSafe verifies every method tolerates a nil receiver,
// matching the Exporter convention elsewhere in this package.
func TestQueryLogWriter_NilSafe(t *testing.T) {
	var w *queryLogWriter
	w.Submit(&models.DNSQuery{Domain: "example.com"}, "allow") // must not panic
	if d := w.Dropped(); d != 0 {
		t.Errorf("Dropped() on nil = %d, want 0", d)
	}
	w.Close() // must not panic
}
