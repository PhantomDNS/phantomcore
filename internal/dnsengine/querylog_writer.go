// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"sync"
	"sync/atomic"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/metrics"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

// defaultQueryLogBufferSize and defaultQueryLogWorkers are used whenever the
// operator leaves DataPlaneConfig's QueryLogBufferSize/QueryLogWorkers at
// their zero value. 1024 in-flight rows is generous slack for a burst while
// still bounding memory; 2 workers is enough to keep up with normal query
// volume against a single SQLite file without over-parallelizing writes to it.
const (
	defaultQueryLogBufferSize = 1024
	defaultQueryLogWorkers    = 2
)

// queryLogEntry is one persisted row plus the stats bucket it should be
// counted under, queued together so a worker does both in one dequeue.
type queryLogEntry struct {
	query       *models.DNSQuery
	statsAction string
}

// queryLogWriter persists query log rows asynchronously through a bounded
// queue drained by a small, fixed pool of workers. It exists so a burst of
// DNS queries never spawns one goroutine per query (the previous behaviour):
// under sustained SQLite write contention that unbounded fan-out could pile
// up hundreds of in-flight goroutines all blocked on the same file. The
// queue is drop-on-full: logQuery must never block the query path waiting
// for a slow write, so once the buffer is saturated new rows are dropped and
// counted rather than queued. A nil *queryLogWriter is a valid no-op.
type queryLogWriter struct {
	queue      chan queryLogEntry
	queryLog   repositories.QueryLogRepository
	statistics repositories.StatisticsRepository
	qm         *metrics.QueryMetrics

	wg        sync.WaitGroup
	closeOnce sync.Once
	dropped   atomic.Uint64
}

// newQueryLogWriter builds a queryLogWriter and starts its worker pool.
// bufferSize and workers <= 0 fall back to the package defaults. qm may be
// nil (drops are still counted locally via Dropped(), just not surfaced
// through /metrics).
func newQueryLogWriter(queryLog repositories.QueryLogRepository, statistics repositories.StatisticsRepository, qm *metrics.QueryMetrics, bufferSize, workers int) *queryLogWriter {
	if bufferSize <= 0 {
		bufferSize = defaultQueryLogBufferSize
	}
	if workers <= 0 {
		workers = defaultQueryLogWorkers
	}

	w := &queryLogWriter{
		queue:      make(chan queryLogEntry, bufferSize),
		queryLog:   queryLog,
		statistics: statistics,
		qm:         qm,
	}

	w.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go w.run()
	}
	return w
}

// Submit enqueues a row for persistence. It never blocks: if the queue is
// full the entry is dropped and the drop counter (local + metrics, when
// wired) is incremented. Safe to call on a nil receiver.
func (w *queryLogWriter) Submit(q *models.DNSQuery, statsAction string) {
	if w == nil {
		return
	}
	select {
	case w.queue <- queryLogEntry{query: q, statsAction: statsAction}:
	default:
		n := w.dropped.Add(1)
		if w.qm != nil {
			w.qm.RecordQueryLogDropped()
		}
		// Log sparingly to avoid amplifying pressure under sustained overflow.
		if n == 1 || n%1024 == 0 {
			logger.Log.Warnf("query log writer: queue full, dropped %d entries", n)
		}
	}
}

// Dropped returns the total number of rows dropped due to a full queue.
// Safe to call on a nil receiver.
func (w *queryLogWriter) Dropped() uint64 {
	if w == nil {
		return 0
	}
	return w.dropped.Load()
}

// Close stops accepting new work, waits for every worker to drain the
// remaining queued entries, and returns once all in-flight rows have been
// persisted. Safe to call multiple times and on a nil receiver.
func (w *queryLogWriter) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		close(w.queue)
		w.wg.Wait()
	})
}

func (w *queryLogWriter) run() {
	defer w.wg.Done()
	for e := range w.queue {
		if err := w.queryLog.Save(e.query); err != nil {
			logger.Log.Errorf("Failed to log query: %v", err)
		}
		if w.statistics != nil {
			if err := w.statistics.IncrementCounter(e.statsAction); err != nil {
				logger.Log.Errorf("Failed to increment stats: %v", err)
			}
		}
	}
}
