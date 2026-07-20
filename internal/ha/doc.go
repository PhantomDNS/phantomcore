// SPDX-License-Identifier: GPL-3.0-or-later

// Package ha provides an active-passive high-availability foundation for
// HydraDNS. It is a deliberately small first increment, NOT a full clustering
// solution.
//
// # Scope and model
//
// This package implements VRRP-style active-passive failover:
//
//   - Exactly one node is "active" (holds the virtual IP and serves traffic)
//     at a time; the other node is a warm "standby".
//   - A node is statically assigned a Role of primary or backup. The primary
//     is the preferred active node. The backup promotes itself to active only
//     when it detects that the peer (the primary) is down, and demotes back to
//     standby once the peer recovers (preemption).
//   - Failover of the actual virtual IP address is performed by keepalived
//     (VRRP) at the network layer. This package (a) tracks peer liveness and
//     exposes an authoritative "am I active / should I take over" signal for
//     the application, and (b) generates a valid keepalived.conf for the
//     operator.
//
// # What this is NOT
//
// This is active-passive failover, not shared-state clustering. There is no
// shared database, no state replication, no consensus/quorum, and no
// split-brain arbitration beyond the static primary/backup roles and VRRP
// priorities. Both nodes are expected to be configured against the same
// upstream sources independently. If you need true multi-active clustering
// with shared state, that is explicitly out of scope for this increment.
//
// The heartbeat state machine (Manager) is fully deterministic and testable:
// the clock and the peer health check are injectable, so no real network or
// wall-clock time is required to exercise it.
package ha
