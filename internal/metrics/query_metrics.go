// SPDX-License-Identifier: GPL-3.0-or-later
package metrics

import (
	"math"
	"sync/atomic"
	"time"
)

type metricsSlice struct {
	startUnix int64 // unix timestamp (seconds) for slice start

	total   atomic.Uint64
	errors  atomic.Uint64
	blocked atomic.Uint64

	latency [BucketCount]atomic.Uint64
}

type QueryMetrics struct {
	windowSize time.Duration
	sliceSize  time.Duration

	slices  []metricsSlice
	current atomic.Uint32
}

const (
	defaultWindowSize = 5 * time.Minute
	defaultSliceSize  = 30 * time.Second
)

type AggregatedMetrics struct {
	Total   uint64
	Errors  uint64
	Blocked uint64

	Buckets [BucketCount]uint64
}

func NewQueryMetrics() *QueryMetrics {
	sliceCount := int(defaultWindowSize / defaultSliceSize)

	m := &QueryMetrics{
		windowSize: defaultWindowSize,
		sliceSize:  defaultSliceSize,
		slices:     make([]metricsSlice, sliceCount),
	}

	now := time.Now().Unix()
	for i := range m.slices {
		m.slices[i].startUnix = now
	}

	return m
}

func (m *QueryMetrics) currentSlice() *metricsSlice {
	now := time.Now().Unix()
	idx := int(m.current.Load())

	s := &m.slices[idx]

	// Still within the slice
	if now < s.startUnix+int64(m.sliceSize.Seconds()) {
		return s
	}

	// Rotate to next slice
	next := (idx + 1) % len(m.slices)

	// Reset the next slice
	m.slices[next] = metricsSlice{
		startUnix: now,
	}

	m.current.Store(uint32(next))
	return &m.slices[next]
}

func (m *QueryMetrics) Record(elapsed time.Duration, success bool) {
	s := m.currentSlice()

	s.total.Add(1)
	if !success {
		s.errors.Add(1)
	}

	b := BucketForLatency(elapsed)
	s.latency[b].Add(1)
}

// RecordBlocked increments the blocked-query counter for the current window
// slice. It tracks queries denied by the blocklist or a deny policy so that a
// rolling blocked percentage can be derived alongside total/error counts.
func (m *QueryMetrics) RecordBlocked() {
	s := m.currentSlice()
	s.blocked.Add(1)
}

// Window returns the rolling window duration the metrics are aggregated over.
func (m *QueryMetrics) Window() time.Duration {
	return m.windowSize
}

func (m *QueryMetrics) Aggregate() AggregatedMetrics {
	var out AggregatedMetrics

	now := time.Now().Unix()
	cutoff := now - int64(m.windowSize.Seconds())

	for i := range m.slices {
		s := &m.slices[i]
		if s.startUnix < cutoff {
			// Slice is outside the window
			continue
		}

		out.Total += s.total.Load()
		out.Errors += s.errors.Load()
		out.Blocked += s.blocked.Load()

		for b := 0; b < int(BucketCount); b++ {
			out.Buckets[b] += s.latency[b].Load()
		}
	}
	return out
}

func EstimatePercentile(buckets [BucketCount]uint64, p float64) time.Duration {
	var total uint64
	for _, c := range buckets {
		total += c
	}

	if total == 0 {
		return 0
	}
	target := uint64(math.Ceil(float64(total) * p))
	if target == 0 {
		target = 1
	}

	var cumulative uint64
	for i, c := range buckets {
		cumulative += c
		if cumulative >= target {
			return BucketUpperBound(LatencyBucket(i))
		}
	}

	return BucketUpperBound(BucketGTE500ms)
}
