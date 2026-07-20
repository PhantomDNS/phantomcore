// SPDX-License-Identifier: GPL-3.0-or-later
package watchdog

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestCheck_RecoversAfterThreshold verifies that recovery fires only after the
// probe reports unhealthy for FailureThreshold consecutive ticks.
func TestCheck_RecoversAfterThreshold(t *testing.T) {
	var recoveries int
	w := New(
		Config{Interval: time.Second, FailureThreshold: 3},
		func() bool { return false }, // always unhealthy
		func() { recoveries++ },
		nil,
	)

	// First two unhealthy ticks: no recovery yet.
	if w.check() {
		t.Fatal("tick 1 should not trigger recovery")
	}
	if w.check() {
		t.Fatal("tick 2 should not trigger recovery")
	}
	if recoveries != 0 {
		t.Fatalf("expected 0 recoveries before threshold, got %d", recoveries)
	}

	// Third consecutive unhealthy tick: recovery fires.
	if !w.check() {
		t.Fatal("tick 3 should trigger recovery")
	}
	if recoveries != 1 {
		t.Fatalf("expected exactly 1 recovery at threshold, got %d", recoveries)
	}
	if w.Healthy() {
		t.Fatal("watchdog should report unhealthy after failing probes")
	}
}

// TestCheck_HealthyNoAction verifies that a healthy probe never triggers
// recovery and keeps the health flag set.
func TestCheck_HealthyNoAction(t *testing.T) {
	var recoveries int
	w := New(
		Config{Interval: time.Second, FailureThreshold: 3},
		func() bool { return true }, // always healthy
		func() { recoveries++ },
		nil,
	)

	for i := 0; i < 10; i++ {
		if w.check() {
			t.Fatalf("healthy probe must not trigger recovery (tick %d)", i)
		}
	}
	if recoveries != 0 {
		t.Fatalf("expected 0 recoveries when healthy, got %d", recoveries)
	}
	if !w.Healthy() {
		t.Fatal("watchdog should report healthy when probe is healthy")
	}
}

// TestCheck_IntermittentResetsCounter verifies that a single healthy tick resets
// the consecutive-failure counter, so recovery requires N *consecutive* failures.
func TestCheck_IntermittentResetsCounter(t *testing.T) {
	var recoveries int
	healthy := false
	w := New(
		Config{Interval: time.Second, FailureThreshold: 3},
		func() bool { return healthy },
		func() { recoveries++ },
		nil,
	)

	// Two failures, then a healthy tick resets the counter.
	w.check()
	w.check()
	healthy = true
	w.check()
	if !w.Healthy() {
		t.Fatal("should be healthy after a healthy tick")
	}

	// Two more failures: still below threshold because the counter was reset.
	healthy = false
	w.check()
	if w.check() {
		t.Fatal("recovery should not fire: only 2 consecutive failures after reset")
	}
	if recoveries != 0 {
		t.Fatalf("expected 0 recoveries, got %d", recoveries)
	}
}

// TestCheck_BackoffAfterRecovery verifies the watchdog requires a fresh full
// threshold of failures before recovering again (no tight recovery loop).
func TestCheck_BackoffAfterRecovery(t *testing.T) {
	var recoveries int
	w := New(
		Config{Interval: time.Second, FailureThreshold: 2},
		func() bool { return false },
		func() { recoveries++ },
		nil,
	)

	w.check() // 1
	w.check() // 2 -> recover
	if recoveries != 1 {
		t.Fatalf("expected 1 recovery, got %d", recoveries)
	}
	w.check() // 1 (counter was reset)
	if recoveries != 1 {
		t.Fatalf("expected still 1 recovery on next tick, got %d", recoveries)
	}
	w.check() // 2 -> recover again
	if recoveries != 2 {
		t.Fatalf("expected 2 recoveries, got %d", recoveries)
	}
}

// TestDisabled_IsNoOp verifies that a non-positive interval disables the
// watchdog: Enabled is false and Start never invokes the probe or recovery.
func TestDisabled_IsNoOp(t *testing.T) {
	var probeCalls, recoveries int32
	w := New(
		Config{Interval: 0},
		func() bool { atomic.AddInt32(&probeCalls, 1); return false },
		func() { atomic.AddInt32(&recoveries, 1) },
		nil,
	)

	if w.Enabled() {
		t.Fatal("watchdog with interval 0 must be disabled")
	}

	// Start must be a no-op: fail the injected ticker if it is ever used.
	w.newTicker = func(time.Duration) (<-chan time.Time, func()) {
		t.Fatal("disabled watchdog must not create a ticker")
		return nil, func() {}
	}
	w.Start(context.Background())

	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&probeCalls) != 0 {
		t.Fatalf("disabled watchdog must not probe, got %d calls", probeCalls)
	}
	if atomic.LoadInt32(&recoveries) != 0 {
		t.Fatalf("disabled watchdog must not recover, got %d", recoveries)
	}
}

// TestProbePanic_TreatedAsUnhealthy verifies a panicking probe is contained and
// counted as an unhealthy tick rather than crashing the process.
func TestProbePanic_TreatedAsUnhealthy(t *testing.T) {
	var recoveries int
	w := New(
		Config{Interval: time.Second, FailureThreshold: 1},
		func() bool { panic("probe boom") },
		func() { recoveries++ },
		nil,
	)

	if !w.check() {
		t.Fatal("panicking probe should count as unhealthy and hit threshold=1")
	}
	if recoveries != 1 {
		t.Fatalf("expected recovery after panicking probe, got %d", recoveries)
	}
}

// TestRun_DriveWithInjectedTicker exercises the full Start/run loop
// deterministically by injecting a manual tick channel (an injected clock),
// with no reliance on real time cadence.
func TestRun_DriveWithInjectedTicker(t *testing.T) {
	ticks := make(chan time.Time)
	recovered := make(chan struct{}, 1)

	w := New(
		Config{Interval: time.Hour, FailureThreshold: 3},
		func() bool { return false },
		func() { recovered <- struct{}{} },
		nil,
	)
	w.newTicker = func(time.Duration) (<-chan time.Time, func()) {
		return ticks, func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	// Drive three unhealthy ticks; the third must invoke recovery.
	for i := 0; i < 3; i++ {
		ticks <- time.Now()
	}

	select {
	case <-recovered:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("recovery was not invoked within timeout")
	}

	cancel()
}
