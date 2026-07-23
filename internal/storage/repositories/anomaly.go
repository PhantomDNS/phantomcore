// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

// This file computes an anomaly digest: notable deltas between a current window
// and a prior window (e.g. a blocked-rate spike, or a single client surging in
// volume). The digest is a pure computed struct — delivery/notification of it is
// intentionally handled elsewhere.

// AnomalyThresholds controls what counts as "notable". Zero-value thresholds are
// replaced with sensible defaults by DefaultAnomalyThresholds, so callers can
// pass an empty struct.
type AnomalyThresholds struct {
	// BlockedRateSpikePoints is the minimum increase in blocked-rate, in
	// percentage points (0..100), for the spike flag to trip.
	BlockedRateSpikePoints float64
	// ClientSurgeFactor is the minimum current/prior volume ratio for a client
	// to be reported as surging.
	ClientSurgeFactor float64
	// ClientSurgeMinQueries is the minimum current-window volume a client must
	// have before a surge is reported, so a jump from 1 to 4 queries is ignored.
	ClientSurgeMinQueries int64
}

// DefaultAnomalyThresholds returns the tuned defaults used when a threshold is
// left at its zero value.
func DefaultAnomalyThresholds() AnomalyThresholds {
	return AnomalyThresholds{
		BlockedRateSpikePoints: 10,
		ClientSurgeFactor:      3,
		ClientSurgeMinQueries:  20,
	}
}

// withDefaults fills any zero-value threshold with its default.
func (t AnomalyThresholds) withDefaults() AnomalyThresholds {
	d := DefaultAnomalyThresholds()
	if t.BlockedRateSpikePoints <= 0 {
		t.BlockedRateSpikePoints = d.BlockedRateSpikePoints
	}
	if t.ClientSurgeFactor <= 0 {
		t.ClientSurgeFactor = d.ClientSurgeFactor
	}
	if t.ClientSurgeMinQueries <= 0 {
		t.ClientSurgeMinQueries = d.ClientSurgeMinQueries
	}
	return t
}

// WindowStats is the minimal per-window summary the anomaly computation needs:
// total and blocked volume plus per-client totals. It is produced by
// GatherWindowStats and consumed by ComputeAnomalyDigest.
type WindowStats struct {
	Total   int64
	Blocked int64
	Clients []ClientActivity
}

// BlockedRate returns the blocked share of the window as a percentage (0..100),
// or 0 when the window is empty.
func (w WindowStats) BlockedRate() float64 {
	if w.Total <= 0 {
		return 0
	}
	return float64(w.Blocked) / float64(w.Total) * 100
}

// ClientSurge describes a single client whose volume grew notably versus the
// prior window.
type ClientSurge struct {
	ClientIP     string  `json:"client_ip"`
	Current      int64   `json:"current"`
	Prior        int64   `json:"prior"`
	GrowthFactor float64 `json:"growth_factor"`
}

// AnomalyDigest is the computed comparison between a current and a prior window.
type AnomalyDigest struct {
	TotalCurrent int64 `json:"total_current"`
	TotalPrior   int64 `json:"total_prior"`
	TotalDelta   int64 `json:"total_delta"`

	BlockedRateCurrent float64 `json:"blocked_rate_current"`
	BlockedRatePrior   float64 `json:"blocked_rate_prior"`
	// BlockedRateDeltaPoints is current minus prior, in percentage points.
	BlockedRateDeltaPoints float64 `json:"blocked_rate_delta_points"`
	BlockedRateSpike       bool    `json:"blocked_rate_spike"`

	SurgingClients []ClientSurge `json:"surging_clients"`
}

// ComputeAnomalyDigest compares two window summaries and returns the notable
// deltas. It is pure and deterministic: no clock, no I/O, and surging clients
// are returned in a stable order (largest growth first, client IP as
// tie-break). A client with zero prior volume but current volume at or above
// ClientSurgeMinQueries is treated as a surge (growth factor reported as +Inf's
// stand-in: current/1).
func ComputeAnomalyDigest(current, prior WindowStats, cfg AnomalyThresholds) AnomalyDigest {
	cfg = cfg.withDefaults()

	digest := AnomalyDigest{
		TotalCurrent:           current.Total,
		TotalPrior:             prior.Total,
		TotalDelta:             current.Total - prior.Total,
		BlockedRateCurrent:     current.BlockedRate(),
		BlockedRatePrior:       prior.BlockedRate(),
		BlockedRateDeltaPoints: current.BlockedRate() - prior.BlockedRate(),
	}
	digest.BlockedRateSpike = digest.BlockedRateDeltaPoints >= cfg.BlockedRateSpikePoints

	priorByClient := make(map[string]int64, len(prior.Clients))
	for _, c := range prior.Clients {
		priorByClient[c.ClientIP] = c.Total
	}

	var surges []ClientSurge
	for _, c := range current.Clients {
		if c.Total < cfg.ClientSurgeMinQueries {
			continue
		}
		priorTotal := priorByClient[c.ClientIP]
		// Use a floor of 1 for the prior so a brand-new client still yields a
		// finite, comparable growth factor.
		denom := priorTotal
		if denom < 1 {
			denom = 1
		}
		factor := float64(c.Total) / float64(denom)
		if factor < cfg.ClientSurgeFactor {
			continue
		}
		surges = append(surges, ClientSurge{
			ClientIP:     c.ClientIP,
			Current:      c.Total,
			Prior:        priorTotal,
			GrowthFactor: factor,
		})
	}
	sortClientSurges(surges)
	digest.SurgingClients = surges
	return digest
}

// sortClientSurges orders surges by growth factor desc, then client IP asc, for
// deterministic output.
func sortClientSurges(s []ClientSurge) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0; j-- {
			a, b := s[j-1], s[j]
			less := b.GrowthFactor > a.GrowthFactor ||
				(b.GrowthFactor == a.GrowthFactor && b.ClientIP < a.ClientIP)
			if !less {
				break
			}
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// GatherWindowStats collects the totals and per-client volumes needed to build
// an anomaly digest for a single window. It reuses the same indexed, bounded
// aggregates as the rollup endpoints: the per-client list is capped at the
// window's clamped top-N so a pathological number of distinct clients cannot
// blow up the digest.
func (r *GormQueryLogRepo) GatherWindowStats(w AnalyticsWindow) (WindowStats, error) {
	var totals struct {
		Total   int64
		Blocked int64
	}
	if err := r.scopedByWindow(w).
		Select("COUNT(*) AS total, " + blockedSumExpr + " AS blocked").
		Scan(&totals).Error; err != nil {
		return WindowStats{}, err
	}

	clients, err := r.TopClients(w)
	if err != nil {
		return WindowStats{}, err
	}

	return WindowStats{
		Total:   totals.Total,
		Blocked: totals.Blocked,
		Clients: clients,
	}, nil
}

// AnomalyDigestBetween gathers stats for the current and prior windows and
// returns the computed digest. Delivery of the digest is intentionally out of
// scope here.
func (r *GormQueryLogRepo) AnomalyDigestBetween(current, prior AnalyticsWindow, cfg AnomalyThresholds) (AnomalyDigest, error) {
	cur, err := r.GatherWindowStats(current)
	if err != nil {
		return AnomalyDigest{}, err
	}
	pri, err := r.GatherWindowStats(prior)
	if err != nil {
		return AnomalyDigest{}, err
	}
	return ComputeAnomalyDigest(cur, pri, cfg), nil
}
