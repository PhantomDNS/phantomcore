// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import "testing"

func TestComputeAnomalyDigest_BlockedRateSpike(t *testing.T) {
	current := WindowStats{Total: 100, Blocked: 40} // 40%
	prior := WindowStats{Total: 100, Blocked: 20}   // 20%

	d := ComputeAnomalyDigest(current, prior, AnomalyThresholds{})
	if d.BlockedRateCurrent != 40 || d.BlockedRatePrior != 20 {
		t.Fatalf("rates wrong: cur=%f prior=%f", d.BlockedRateCurrent, d.BlockedRatePrior)
	}
	if d.BlockedRateDeltaPoints != 20 {
		t.Errorf("expected +20 points, got %f", d.BlockedRateDeltaPoints)
	}
	if !d.BlockedRateSpike {
		t.Errorf("expected spike=true for +20 points against default 10-point threshold")
	}
	if d.TotalDelta != 0 {
		t.Errorf("expected total delta 0, got %d", d.TotalDelta)
	}
}

func TestComputeAnomalyDigest_NoSpikeBelowThreshold(t *testing.T) {
	current := WindowStats{Total: 100, Blocked: 25} // 25%
	prior := WindowStats{Total: 100, Blocked: 20}   // 20%, +5 points < 10

	d := ComputeAnomalyDigest(current, prior, AnomalyThresholds{})
	if d.BlockedRateSpike {
		t.Errorf("expected no spike for +5 points, got spike=true (delta=%f)", d.BlockedRateDeltaPoints)
	}
}

func TestComputeAnomalyDigest_CustomThreshold(t *testing.T) {
	current := WindowStats{Total: 100, Blocked: 25}
	prior := WindowStats{Total: 100, Blocked: 20}

	// Lower the spike threshold to 4 points; +5 now trips it.
	d := ComputeAnomalyDigest(current, prior, AnomalyThresholds{BlockedRateSpikePoints: 4})
	if !d.BlockedRateSpike {
		t.Errorf("expected spike with 4-point threshold and +5 delta")
	}
}

func TestComputeAnomalyDigest_EmptyPriorRate(t *testing.T) {
	// Empty prior window: blocked rate is defined as 0, not NaN.
	current := WindowStats{Total: 50, Blocked: 30}
	prior := WindowStats{}

	d := ComputeAnomalyDigest(current, prior, AnomalyThresholds{})
	if d.BlockedRatePrior != 0 {
		t.Errorf("expected prior rate 0 for empty window, got %f", d.BlockedRatePrior)
	}
	if d.TotalDelta != 50 {
		t.Errorf("expected total delta 50, got %d", d.TotalDelta)
	}
	if !d.BlockedRateSpike {
		t.Errorf("60%% vs 0%% should be a spike")
	}
}

func TestComputeAnomalyDigest_ClientSurge(t *testing.T) {
	current := WindowStats{
		Total: 200, Blocked: 10,
		Clients: []ClientActivity{
			{ClientIP: "10.0.0.1", Total: 120}, // 30 -> 120 = 4x, above floor
			{ClientIP: "10.0.0.2", Total: 25},  // 20 -> 25 = 1.25x, not a surge
			{ClientIP: "10.0.0.3", Total: 60},  // new client, 0 -> 60
			{ClientIP: "10.0.0.4", Total: 5},   // below min-queries floor, ignored
		},
	}
	prior := WindowStats{
		Total: 60,
		Clients: []ClientActivity{
			{ClientIP: "10.0.0.1", Total: 30},
			{ClientIP: "10.0.0.2", Total: 20},
		},
	}

	d := ComputeAnomalyDigest(current, prior, AnomalyThresholds{})

	if len(d.SurgingClients) != 2 {
		t.Fatalf("expected 2 surging clients, got %d (%+v)", len(d.SurgingClients), d.SurgingClients)
	}
	// New client 10.0.0.3: 0 -> 60 => growth 60 (denom floored to 1) beats 4x.
	// Ordered by growth factor desc, so it should be first.
	if d.SurgingClients[0].ClientIP != "10.0.0.3" {
		t.Errorf("expected new client 10.0.0.3 first by growth, got %+v", d.SurgingClients[0])
	}
	if d.SurgingClients[0].Prior != 0 || d.SurgingClients[0].Current != 60 {
		t.Errorf("10.0.0.3 surge fields wrong: %+v", d.SurgingClients[0])
	}
	if d.SurgingClients[1].ClientIP != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 as second surge, got %+v", d.SurgingClients[1])
	}
	if d.SurgingClients[1].GrowthFactor != 4 {
		t.Errorf("expected growth factor 4 for 10.0.0.1, got %f", d.SurgingClients[1].GrowthFactor)
	}
	// 10.0.0.2 (1.25x) and 10.0.0.4 (below floor) must be excluded.
	for _, s := range d.SurgingClients {
		if s.ClientIP == "10.0.0.2" || s.ClientIP == "10.0.0.4" {
			t.Errorf("client %q should not be reported as surging", s.ClientIP)
		}
	}
}

func TestComputeAnomalyDigest_Deterministic(t *testing.T) {
	// Same growth factor -> tie-broken by client IP ascending.
	current := WindowStats{
		Clients: []ClientActivity{
			{ClientIP: "10.0.0.5", Total: 40},
			{ClientIP: "10.0.0.2", Total: 40},
		},
	}
	prior := WindowStats{
		Clients: []ClientActivity{
			{ClientIP: "10.0.0.5", Total: 10},
			{ClientIP: "10.0.0.2", Total: 10},
		},
	}
	d := ComputeAnomalyDigest(current, prior, AnomalyThresholds{})
	if len(d.SurgingClients) != 2 {
		t.Fatalf("expected 2 surges, got %d", len(d.SurgingClients))
	}
	if d.SurgingClients[0].ClientIP != "10.0.0.2" || d.SurgingClients[1].ClientIP != "10.0.0.5" {
		t.Errorf("expected IP-ascending tie-break, got %q then %q",
			d.SurgingClients[0].ClientIP, d.SurgingClients[1].ClientIP)
	}
}
