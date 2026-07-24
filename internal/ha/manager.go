// SPDX-License-Identifier: GPL-3.0-or-later

package ha

import (
	"context"
	"net"
	"sync"
	"time"
)

// State is the operational state of this node.
type State string

const (
	// StateActive means this node considers itself the active node: it should
	// hold the VIP and serve traffic.
	StateActive State = "active"
	// StateStandby means this node is passive and waiting; the peer is active.
	StateStandby State = "standby"
)

// HealthCheckFunc probes the peer at addr and reports whether it is reachable.
// It must be non-blocking beyond a bounded timeout and must honor ctx.
type HealthCheckFunc func(ctx context.Context, addr string) bool

// Manager tracks peer liveness and derives this node's active/standby state
// for an active-passive pair. It is safe for concurrent use.
//
// The state machine is deterministic: with a fixed injected clock and health
// check it produces identical transitions, so it can be tested without any
// real network or wall-clock timing.
type Manager struct {
	cfg         Config
	now         func() time.Time
	healthCheck HealthCheckFunc

	mu              sync.Mutex
	state           State
	peerUp          bool
	consecFailures  int
	consecSuccesses int
	lastTransition  time.Time
}

// Option customizes a Manager (used for dependency injection in tests).
type Option func(*Manager)

// WithClock injects a clock. Defaults to time.Now.
func WithClock(now func() time.Time) Option {
	return func(m *Manager) { m.now = now }
}

// WithHealthCheck injects the peer probe. Defaults to a bounded TCP dial.
func WithHealthCheck(fn HealthCheckFunc) Option {
	return func(m *Manager) { m.healthCheck = fn }
}

// New constructs a Manager. It validates the configuration; a disabled config
// yields a Manager that reports StateActive and whose Run loop is a no-op
// (a standalone node serves traffic normally).
func New(cfg Config, opts ...Option) (*Manager, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &Manager{
		cfg: cfg,
		now: time.Now,
		// Optimistic startup: assume the peer is alive so a starting backup
		// begins in standby and we avoid a dual-active window.
		peerUp: true,
	}
	m.healthCheck = tcpHealthCheck(cfg.DialTimeout)
	for _, opt := range opts {
		opt(m)
	}

	m.state = m.desiredStateLocked()
	m.lastTransition = m.now()
	return m, nil
}

// desiredStateLocked computes the state implied by the current role and peer
// liveness. Callers may hold m.mu but it is not required for the read of cfg.
func (m *Manager) desiredStateLocked() State {
	if !m.cfg.Enabled {
		return StateActive
	}
	if m.cfg.Role == RolePrimary {
		// The primary is the preferred active node and stays active whenever
		// it is running, regardless of peer state.
		return StateActive
	}
	// Backup: active only while the peer (primary) is down.
	if m.peerUp {
		return StateStandby
	}
	return StateActive
}

// Tick applies a single peer-health observation to the state machine and
// returns the resulting state. It is the deterministic core of the manager:
// the same sequence of observations always yields the same transitions.
func (m *Manager) Tick(peerHealthy bool) State {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enabled {
		return StateActive
	}

	// Apply hysteresis to peer liveness to avoid flapping on a single blip.
	if peerHealthy {
		m.consecSuccesses++
		m.consecFailures = 0
		if !m.peerUp && m.consecSuccesses >= m.cfg.RecoveryThreshold {
			m.peerUp = true
		}
	} else {
		m.consecFailures++
		m.consecSuccesses = 0
		if m.peerUp && m.consecFailures >= m.cfg.FailureThreshold {
			m.peerUp = false
		}
	}

	next := m.desiredStateLocked()
	if next != m.state {
		m.state = next
		m.lastTransition = m.now()
	}
	return m.state
}

// probeOnce runs a single peer probe through the injected health check and
// feeds the result into the state machine. It returns the resulting state.
func (m *Manager) probeOnce(ctx context.Context) State {
	healthy := m.healthCheck(ctx, m.cfg.PeerAddr)
	return m.Tick(healthy)
}

// Run drives the heartbeat loop until ctx is cancelled. When HA is disabled it
// returns immediately. Run is a thin wrapper over probeOnce; all state logic is
// in Tick, which is tested directly.
func (m *Manager) Run(ctx context.Context) {
	if !m.cfg.Enabled {
		return
	}
	ticker := time.NewTicker(m.cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeOnce(ctx)
		}
	}
}

// State returns this node's current operational state.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// IsActive reports whether this node should currently hold the VIP and serve
// traffic ("am I primary / should I take over"). A disabled manager is always
// active (standalone operation).
func (m *Manager) IsActive() bool {
	return m.State() == StateActive
}

// ShouldTakeOver reports whether this backup node has promoted itself because
// the peer is down. It is always false for the primary and when disabled.
func (m *Manager) ShouldTakeOver() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Enabled && m.cfg.Role == RoleBackup && m.state == StateActive
}

// PeerUp reports the last known peer liveness (after hysteresis).
func (m *Manager) PeerUp() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.peerUp
}

// Role returns the configured role.
func (m *Manager) Role() Role { return m.cfg.Role }

// Status is a point-in-time snapshot of manager state for observability.
type Status struct {
	Enabled        bool      `json:"enabled"`
	Role           Role      `json:"role"`
	State          State     `json:"state"`
	PeerAddr       string    `json:"peer_addr"`
	PeerUp         bool      `json:"peer_up"`
	VIP            string    `json:"vip"`
	LastTransition time.Time `json:"last_transition"`
}

// Status returns a snapshot of the manager's current state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Enabled:        m.cfg.Enabled,
		Role:           m.cfg.Role,
		State:          m.state,
		PeerAddr:       m.cfg.PeerAddr,
		PeerUp:         m.peerUp,
		VIP:            m.cfg.VIP,
		LastTransition: m.lastTransition,
	}
}

// tcpHealthCheck returns a HealthCheckFunc that treats a successful TCP
// connection to the peer within timeout as "peer up".
func tcpHealthCheck(timeout time.Duration) HealthCheckFunc {
	return func(ctx context.Context, addr string) bool {
		if addr == "" {
			return false
		}
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
}
