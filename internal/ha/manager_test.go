// SPDX-License-Identifier: GPL-3.0-or-later

package ha

import (
	"context"
	"testing"
	"time"
)

// fixedClock returns a clock that always reports the same instant.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func newTestManager(t *testing.T, cfg Config, opts ...Option) *Manager {
	t.Helper()
	m, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	return m
}

func TestManager_Disabled_IsAlwaysActiveAndOff(t *testing.T) {
	// Zero config is disabled and must validate.
	m := newTestManager(t, Config{Enabled: false})

	if !m.IsActive() {
		t.Fatalf("disabled manager should be active (standalone), got state %q", m.State())
	}
	if m.State() != StateActive {
		t.Fatalf("disabled state = %q, want %q", m.State(), StateActive)
	}
	// Ticks must not change anything when disabled.
	for i := 0; i < 5; i++ {
		if got := m.Tick(false); got != StateActive {
			t.Fatalf("disabled Tick(false) = %q, want %q", got, StateActive)
		}
	}
	if m.ShouldTakeOver() {
		t.Fatalf("disabled manager should never take over")
	}

	// Run must return immediately (no ticker, no probing) even without cancel.
	done := make(chan struct{})
	go func() {
		m.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("disabled Run did not return promptly")
	}
}

func TestManager_PrimaryStaysActive(t *testing.T) {
	m := newTestManager(t, Config{
		Enabled:          true,
		Role:             RolePrimary,
		PeerAddr:         "10.0.0.2:9000",
		FailureThreshold: 3,
	})

	if m.State() != StateActive {
		t.Fatalf("primary initial state = %q, want %q", m.State(), StateActive)
	}
	// Peer going down (many failures) must NOT change the primary's state.
	for i := 0; i < 10; i++ {
		if got := m.Tick(false); got != StateActive {
			t.Fatalf("primary Tick(false)#%d = %q, want %q", i, got, StateActive)
		}
	}
	if m.ShouldTakeOver() {
		t.Fatalf("primary must never report ShouldTakeOver")
	}
	// Peer recovery: still active.
	for i := 0; i < 5; i++ {
		if got := m.Tick(true); got != StateActive {
			t.Fatalf("primary Tick(true)#%d = %q, want %q", i, got, StateActive)
		}
	}
}

func TestManager_BackupPromotesOnPeerDown_DemotesOnRecovery(t *testing.T) {
	m := newTestManager(t, Config{
		Enabled:           true,
		Role:              RoleBackup,
		PeerAddr:          "10.0.0.1:9000",
		FailureThreshold:  3,
		RecoveryThreshold: 2,
	})

	// Backup starts in standby (optimistic: peer assumed alive).
	if m.State() != StateStandby {
		t.Fatalf("backup initial state = %q, want %q", m.State(), StateStandby)
	}

	// Below the failure threshold: must remain standby (no flapping).
	if got := m.Tick(false); got != StateStandby {
		t.Fatalf("after 1 failure state = %q, want %q", got, StateStandby)
	}
	if got := m.Tick(false); got != StateStandby {
		t.Fatalf("after 2 failures state = %q, want %q", got, StateStandby)
	}
	// The 3rd consecutive failure crosses the threshold -> promote to active.
	if got := m.Tick(false); got != StateActive {
		t.Fatalf("after 3 failures state = %q, want %q", got, StateActive)
	}
	if !m.ShouldTakeOver() {
		t.Fatalf("promoted backup should report ShouldTakeOver")
	}
	if m.PeerUp() {
		t.Fatalf("peer should be marked down after threshold failures")
	}

	// A single success is below the recovery threshold: stay active.
	if got := m.Tick(true); got != StateActive {
		t.Fatalf("after 1 recovery probe state = %q, want %q", got, StateActive)
	}
	// The 2nd consecutive success crosses recovery threshold -> demote.
	if got := m.Tick(true); got != StateStandby {
		t.Fatalf("after 2 recovery probes state = %q, want %q", got, StateStandby)
	}
	if !m.PeerUp() {
		t.Fatalf("peer should be marked up after recovery")
	}
	if m.ShouldTakeOver() {
		t.Fatalf("demoted backup should not report ShouldTakeOver")
	}
}

func TestManager_BackupFailureCounterResetsOnSuccess(t *testing.T) {
	m := newTestManager(t, Config{
		Enabled:          true,
		Role:             RoleBackup,
		PeerAddr:         "10.0.0.1:9000",
		FailureThreshold: 3,
	})

	// Two failures, then a success should reset the failure streak so the
	// next two failures do NOT promote (would need 3 consecutive).
	m.Tick(false)
	m.Tick(false)
	m.Tick(true) // resets streak
	if got := m.Tick(false); got != StateStandby {
		t.Fatalf("state after reset+1 failure = %q, want %q", got, StateStandby)
	}
	if got := m.Tick(false); got != StateStandby {
		t.Fatalf("state after reset+2 failures = %q, want %q", got, StateStandby)
	}
	if got := m.Tick(false); got != StateActive {
		t.Fatalf("state after reset+3 failures = %q, want %q", got, StateActive)
	}
}

func TestManager_LastTransitionUsesInjectedClock(t *testing.T) {
	instant := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	m := newTestManager(t, Config{
		Enabled:          true,
		Role:             RoleBackup,
		PeerAddr:         "10.0.0.1:9000",
		FailureThreshold: 1,
	}, WithClock(fixedClock(instant)))

	m.Tick(false) // promote -> records transition timestamp
	if got := m.Status().LastTransition; !got.Equal(instant) {
		t.Fatalf("LastTransition = %v, want %v (injected clock)", got, instant)
	}
}

func TestManager_ProbeOnce_UsesInjectedHealthCheck(t *testing.T) {
	peerHealthy := false
	m := newTestManager(t, Config{
		Enabled:          true,
		Role:             RoleBackup,
		PeerAddr:         "10.0.0.1:9000",
		FailureThreshold: 2,
	}, WithHealthCheck(func(_ context.Context, addr string) bool {
		if addr != "10.0.0.1:9000" {
			t.Errorf("probe addr = %q, want peer addr", addr)
		}
		return peerHealthy
	}))

	// Two failing probes cross the threshold and promote the backup — with no
	// real network involved.
	m.probeOnce(context.Background())
	if got := m.probeOnce(context.Background()); got != StateActive {
		t.Fatalf("after 2 failed probes state = %q, want %q", got, StateActive)
	}

	// Recovery via injected health check.
	peerHealthy = true
	m.probeOnce(context.Background())
	m.probeOnce(context.Background())
	m.probeOnce(context.Background())
	if got := m.State(); got != StateStandby {
		t.Fatalf("after recovery probes state = %q, want %q", got, StateStandby)
	}
}

func TestManager_Run_StopsOnContextCancel(t *testing.T) {
	m := newTestManager(t, Config{
		Enabled:       true,
		Role:          RolePrimary,
		PeerAddr:      "10.0.0.2:9000",
		CheckInterval: time.Millisecond,
	}, WithHealthCheck(func(context.Context, string) bool { return true }))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Run did not return after context cancel")
	}
}

func TestNew_InvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing peer", Config{Enabled: true, Role: RolePrimary}},
		{"bad role", Config{Enabled: true, Role: Role("leader"), PeerAddr: "x:1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("New(%+v) expected error, got nil", tc.cfg)
			}
		})
	}
}
