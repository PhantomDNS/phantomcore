// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"net"
	"testing"
)

// acceptForever accepts and holds open every connection made to ln until
// the listener is closed. It exists only to give the TCP pool something
// real to dial; the test never sends any bytes over it.
func acceptForever(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
}

// TestUpstreamPool_ReleaseTCPConn_FreesSlotOnSuccess proves that a slot
// handed out by getTCPConn becomes available again after a successful
// exchange (hadErr=false), not just after a failed one. Regression test
// for a leak where releaseTCPConn only cleared p.inUse[idx] inside the
// hadErr branch, so every clean exchange permanently pinned its slot.
func TestUpstreamPool_ReleaseTCPConn_FreesSlotOnSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	acceptForever(t, ln)

	pool, err := NewUpstreamPool(ln.Addr().String(), 1)
	if err != nil {
		t.Fatalf("NewUpstreamPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	conn1, idx1, err := pool.getTCPConn()
	if err != nil {
		t.Fatalf("getTCPConn failed: %v", err)
	}

	// Simulate a successful exchange: no error, so the connection should
	// be kept open and its slot freed for reuse.
	pool.releaseTCPConn(idx1, false)

	conn2, idx2, err := pool.getTCPConn()
	if err != nil {
		t.Fatalf("expected slot to be reusable after a successful exchange, got error: %v", err)
	}
	if idx2 != idx1 {
		t.Errorf("expected the same slot index to be reused, got %d want %d", idx2, idx1)
	}
	if conn2 != conn1 {
		t.Errorf("expected the pooled connection to be reused rather than redialed")
	}
}

// TestUpstreamPool_ReleaseTCPConn_ClosesOnError proves the existing error
// behavior still holds: a failed exchange closes the connection and the
// slot is redialed fresh next time, but is still immediately reusable.
func TestUpstreamPool_ReleaseTCPConn_ClosesOnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	acceptForever(t, ln)

	pool, err := NewUpstreamPool(ln.Addr().String(), 1)
	if err != nil {
		t.Fatalf("NewUpstreamPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	conn1, idx1, err := pool.getTCPConn()
	if err != nil {
		t.Fatalf("getTCPConn failed: %v", err)
	}

	pool.releaseTCPConn(idx1, true)

	conn2, idx2, err := pool.getTCPConn()
	if err != nil {
		t.Fatalf("expected slot to be reusable after a failed exchange, got error: %v", err)
	}
	if idx2 != idx1 {
		t.Errorf("expected the same slot index to be reused, got %d want %d", idx2, idx1)
	}
	if conn2 == conn1 {
		t.Errorf("expected a fresh dialed connection after an errored exchange, got the same one back")
	}
}

// TestUpstreamPool_TCPPool_DoesNotExhaustUnderRepeatedSuccess exercises the
// pool the way Exchange does across many successful round trips and checks
// the pool never reports itself exhausted, which would indicate a slot
// leak.
func TestUpstreamPool_TCPPool_DoesNotExhaustUnderRepeatedSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	acceptForever(t, ln)

	pool, err := NewUpstreamPool(ln.Addr().String(), 2)
	if err != nil {
		t.Fatalf("NewUpstreamPool failed: %v", err)
	}
	defer func() { _ = pool.Close() }()

	for i := 0; i < 10; i++ {
		_, idx, err := pool.getTCPConn()
		if err != nil {
			t.Fatalf("iteration %d: getTCPConn failed (pool exhausted -> slot leak): %v", i, err)
		}
		pool.releaseTCPConn(idx, false)
	}
}
