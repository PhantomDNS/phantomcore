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

	slices []metricsSlice
	// sliceCount mirrors len(slices) as a uint32, computed once so the
	// rotation path in currentSlice never has to convert an int length.
	sliceCount uint32
	current    atomic.Uint32
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
	// sliceCount is a fixed, small constant derived from the window/slice
	// duration constants above (10 with the current defaults); it can never
	// approach uint32's range, but guard the conversion explicitly rather
	// than assume it.
	if sliceCount <= 0 || sliceCount > math.MaxUint32 {
		sliceCount = 1
	}

	m := &QueryMetrics{
		windowSize: defaultWindowSize,
		sliceSize:  defaultSliceSize,
		slices:     make([]metricsSlice, sliceCount),
		sliceCount: uint32(sliceCount),
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

	// Rotate to next slice. Computed natively in uint32 (the type m.current
	// stores) against the precomputed sliceCount, so there is no int->uint32
	// narrowing conversion on this path.
	next := (m.current.Load() + 1) % m.sliceCount

	// Reset the next slice
	m.slices[next] = metricsSlice{
		startUnix: now,
	}

	m.current.Store(next)
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
