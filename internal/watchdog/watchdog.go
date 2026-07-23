// SPDX-License-Identifier: GPL-3.0-or-later

// Package watchdog provides a lightweight self-heal supervisor for the
// PhantomDNS dataplane, intended for unattended boxes (appliances) where no
// operator is present to notice a stalled resolver.
//
// The watchdog periodically calls an injected liveness Probe. When the probe
// reports unhealthy for a sustained number of consecutive ticks
// (FailureThreshold), it invokes an injected Recovery callback and flips an
// internal health flag. It is deliberately bounded and non-fatal: it never
// terminates the process, contains panics from the probe or recovery callback,
// and backs off after each recovery attempt so it cannot spin in a tight loop.
//
// For hard failures where the whole process is wedged (and this in-process
// goroutine can no longer run), recovery is delegated to the process manager —
// see deploy/hydradns.service, which sets Restart=always for bare-metal
// auto-restart.
package watchdog

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Probe reports whether the supervised dataplane is currently healthy. It must
// be fast and non-blocking; a false return counts as one unhealthy tick. A
// panic inside the probe is treated as unhealthy.
type Probe func() bool

// Recovery attempts to bring the dataplane back to a healthy state (for example
// by re-initialising the DNS listener, or, when an in-process restart is not
// safely in scope, by emitting a critical log line for external supervision).
// It is invoked at most once per sustained unhealthy episode.
type Recovery func()

// Logger is the minimal logging surface the watchdog needs. It is satisfied by
// *logrus.Logger. A nil Logger disables logging.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

const (
	// DefaultInterval is a sane probe cadence for an unattended appliance.
	DefaultInterval = 30 * time.Second
	// DefaultFailureThreshold is the number of consecutive unhealthy probes
	// required before recovery is attempted.
	DefaultFailureThreshold = 3
)

// Config controls watchdog behaviour.
type Config struct {
	// Interval between liveness probes. A value <= 0 disables the watchdog:
	// New returns a watchdog whose Start is a no-op and Enabled reports false.
	Interval time.Duration
	// FailureThreshold is the number of consecutive unhealthy probes that must
	// occur before Recovery is invoked. Values < 1 fall back to
	// DefaultFailureThreshold.
	FailureThreshold int
}

// Watchdog supervises dataplane liveness. Construct one with New and launch it
// with Start. The zero value is not usable.
type Watchdog struct {
	interval  time.Duration
	threshold int
	probe     Probe
	recover   Recovery
	log       Logger

	// newTicker is injectable so tests can drive the loop deterministically
	// without real time. It returns a tick channel and a stop function.
	newTicker func(time.Duration) (<-chan time.Time, func())

	enabled bool
	started atomic.Bool

	mu       sync.Mutex // guards failures
	failures int

	healthy atomic.Bool
}

// New builds a Watchdog. probe and recover may be nil (a nil probe is treated as
// always healthy; a nil recover makes recovery a no-op), which is useful in
// tests. log may be nil to disable logging.
func New(cfg Config, probe Probe, recover Recovery, log Logger) *Watchdog {
	threshold := cfg.FailureThreshold
	if threshold < 1 {
		threshold = DefaultFailureThreshold
	}
	w := &Watchdog{
		interval:  cfg.Interval,
		threshold: threshold,
		probe:     probe,
		recover:   recover,
		log:       log,
		newTicker: realTicker,
		enabled:   cfg.Interval > 0,
	}
	w.healthy.Store(true)
	return w
}

func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Enabled reports whether the watchdog will actually run (interval > 0).
func (w *Watchdog) Enabled() bool { return w.enabled }

// Healthy reports the last observed health state. It starts true and is flipped
// by each probe cycle. Safe for concurrent use.
func (w *Watchdog) Healthy() bool { return w.healthy.Load() }

// Start launches the watchdog loop in a background goroutine and returns
// immediately. It is a no-op if the watchdog is disabled or already started.
// The loop runs until ctx is cancelled.
func (w *Watchdog) Start(ctx context.Context) {
	if !w.enabled {
		w.logf(w.infof, "watchdog disabled (interval <= 0)")
		return
	}
	if !w.started.CompareAndSwap(false, true) {
		return
	}
	go w.run(ctx)
}

func (w *Watchdog) run(ctx context.Context) {
	tickC, stop := w.newTicker(w.interval)
	defer stop()

	w.logf(w.infof, "watchdog started (interval=%s failure_threshold=%d)", w.interval, w.threshold)

	for {
		select {
		case <-ctx.Done():
			w.logf(w.infof, "watchdog stopping: %v", ctx.Err())
			return
		case <-tickC:
			w.check()
		}
	}
}

// check runs a single probe cycle. It is fully synchronous and is the unit under
// test. It returns true if a recovery was triggered on this cycle.
func (w *Watchdog) check() bool {
	healthy := w.safeProbe()

	w.mu.Lock()
	defer w.mu.Unlock()

	if healthy {
		if !w.healthy.Load() {
			w.logf(w.infof, "watchdog: dataplane recovered")
		}
		w.failures = 0
		w.healthy.Store(true)
		return false
	}

	w.failures++
	w.healthy.Store(false)
	w.logf(w.warnf, "watchdog: dataplane unhealthy (%d/%d consecutive)", w.failures, w.threshold)

	if w.failures >= w.threshold {
		w.logf(w.errorf, "watchdog: failure threshold reached (%d), invoking recovery", w.threshold)
		w.safeRecover()
		// Back off: require another full threshold of failures before the next
		// recovery attempt so we never spin in a tight loop.
		w.failures = 0
		return true
	}
	return false
}

func (w *Watchdog) safeProbe() (healthy bool) {
	defer func() {
		if r := recover(); r != nil {
			w.logf(w.errorf, "watchdog: probe panicked: %v", r)
			healthy = false
		}
	}()
	if w.probe == nil {
		return true
	}
	return w.probe()
}

func (w *Watchdog) safeRecover() {
	defer func() {
		if r := recover(); r != nil {
			w.logf(w.errorf, "watchdog: recovery panicked: %v", r)
		}
	}()
	if w.recover != nil {
		w.recover()
	}
}

// logf funnels all logging through a nil-safe helper.
func (w *Watchdog) logf(fn func(string, ...any), format string, args ...any) {
	if w.log == nil || fn == nil {
		return
	}
	fn(format, args...)
}

func (w *Watchdog) infof(format string, args ...any)  { w.log.Infof(format, args...) }
func (w *Watchdog) warnf(format string, args ...any)  { w.log.Warnf(format, args...) }
func (w *Watchdog) errorf(format string, args ...any) { w.log.Errorf(format, args...) }
