// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// Top-N bounds for analytics leaderboards. A caller can never ask an aggregate
// query for an unbounded number of rows.
const (
	// DefaultAnalyticsTopN is used when no (or an invalid) top-N is supplied.
	DefaultAnalyticsTopN = 10
	// MaxAnalyticsTopN caps how many rows a single leaderboard may return.
	MaxAnalyticsTopN = 100
)

// ClampAnalyticsTopN normalizes a requested leaderboard size into the allowed
// bounds. Non-positive values fall back to the default; values above the cap
// are clamped to MaxAnalyticsTopN.
func ClampAnalyticsTopN(n int) int {
	if n <= 0 {
		return DefaultAnalyticsTopN
	}
	if n > MaxAnalyticsTopN {
		return MaxAnalyticsTopN
	}
	return n
}

// AnalyticsWindow scopes an aggregate query to an optional inclusive time range
// and caps how many rows a "top-N" rollup may return. Zero-value time bounds
// mean "no bound"; a non-positive Limit falls back to DefaultAnalyticsTopN.
//
// The window reuses the same indexed Timestamp column and DNSQuery model that
// back the query-log listing added on this branch, so every rollup is served
// from an index and bounded.
type AnalyticsWindow struct {
	From  *time.Time
	To    *time.Time
	Limit int
}

// ClientActivity is one row of the top-clients leaderboard: how many queries a
// client made in the window and how many of them were blocked.
type ClientActivity struct {
	ClientIP string `json:"client_ip"`
	Total    int64  `json:"total"`
	Blocked  int64  `json:"blocked"`
}

// DomainCount is one row of the top-blocked-domains leaderboard.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// CategoryCount is one row of the category breakdown. "Category" here is the
// query's disposition (DNSQuery.Action: allow | block | flagged | redirect) —
// the only low-cardinality, always-populated, indexed categorical dimension the
// query log records per row. Content categories live on policies/blocklists and
// are not stamped onto individual query rows.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// TimeBucket is one hour-wide bucket of a per-client activity timeline.
type TimeBucket struct {
	Bucket  time.Time `json:"bucket"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}

// HeatmapCell is one cell of the category x hour-of-day heatmap: for a given
// hour-of-day (0..23, UTC) and category (disposition), how many queries landed
// there across the window.
type HeatmapCell struct {
	Hour     int    `json:"hour"`
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// blockedSumExpr counts blocked rows inside an aggregate. Kept as a constant so
// every rollup reports "blocked" the same way.
const blockedSumExpr = "SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END)"

// scopedByWindow builds a fresh *gorm.DB scoped to the DNSQuery table and the
// window's inclusive time bounds. Both bounds are optional and use the indexed
// Timestamp column.
func (r *GormQueryLogRepo) scopedByWindow(w AnalyticsWindow) *gorm.DB {
	q := r.db.Model(&models.DNSQuery{})
	if w.From != nil {
		q = q.Where("timestamp >= ?", *w.From)
	}
	if w.To != nil {
		q = q.Where("timestamp <= ?", *w.To)
	}
	return q
}

// TopClients returns the busiest clients in the window, newest-first by total
// query volume, capped at the window's clamped top-N. Each row also carries how
// many of that client's queries were blocked.
func (r *GormQueryLogRepo) TopClients(w AnalyticsWindow) ([]ClientActivity, error) {
	var out []ClientActivity
	err := r.scopedByWindow(w).
		Select("client_ip, COUNT(*) AS total, " + blockedSumExpr + " AS blocked").
		Group("client_ip").
		Order("total DESC, client_ip ASC").
		Limit(ClampAnalyticsTopN(w.Limit)).
		Scan(&out).Error
	return out, err
}

// TopBlockedDomains returns the most-blocked domains in the window, ordered by
// block count desc, capped at the window's clamped top-N. Only rows with
// action = "block" are counted; the action filter is served from an index.
func (r *GormQueryLogRepo) TopBlockedDomains(w AnalyticsWindow) ([]DomainCount, error) {
	var out []DomainCount
	err := r.scopedByWindow(w).
		Where("action = ?", "block").
		Select("domain, COUNT(*) AS count").
		Group("domain").
		Order("count DESC, domain ASC").
		Limit(ClampAnalyticsTopN(w.Limit)).
		Scan(&out).Error
	return out, err
}

// CategoryBreakdown returns the per-disposition query counts across the window,
// ordered by count desc. The result is naturally bounded (one row per distinct
// action) so no top-N cap is applied.
func (r *GormQueryLogRepo) CategoryBreakdown(w AnalyticsWindow) ([]CategoryCount, error) {
	var out []CategoryCount
	err := r.scopedByWindow(w).
		Select("action AS category, COUNT(*) AS count").
		Group("action").
		Order("count DESC, action ASC").
		Scan(&out).Error
	return out, err
}

// ClientTimeline returns an hour-bucketed activity timeline for a single client
// over the window, ordered oldest-first. Each bucket carries the total and
// blocked query counts for that hour. Buckets with no activity are omitted (the
// caller can fill gaps); the number of buckets is bounded by the window length.
func (r *GormQueryLogRepo) ClientTimeline(clientIP string, w AnalyticsWindow) ([]TimeBucket, error) {
	type row struct {
		Bucket  string
		Total   int64
		Blocked int64
	}
	var rows []row
	err := r.scopedByWindow(w).
		Where("client_ip = ?", clientIP).
		Select("strftime('%Y-%m-%d %H:00:00', timestamp) AS bucket, COUNT(*) AS total, " + blockedSumExpr + " AS blocked").
		Group("bucket").
		Order("bucket ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	out := make([]TimeBucket, 0, len(rows))
	for _, rr := range rows {
		t, perr := time.Parse("2006-01-02 15:04:05", rr.Bucket)
		if perr != nil {
			// Skip an unparseable bucket rather than failing the whole rollup.
			continue
		}
		out = append(out, TimeBucket{
			Bucket:  t.UTC(),
			Total:   rr.Total,
			Blocked: rr.Blocked,
		})
	}
	return out, nil
}

// CategoryHourHeatmap returns a category x hour-of-day dataset across the
// window: for each (hour-of-day 0..23, disposition) pair with at least one
// query, the number of queries. The result is bounded to at most 24 * (number
// of distinct actions) cells and ordered deterministically by hour then
// category.
func (r *GormQueryLogRepo) CategoryHourHeatmap(w AnalyticsWindow) ([]HeatmapCell, error) {
	var out []HeatmapCell
	err := r.scopedByWindow(w).
		Select("CAST(strftime('%H', timestamp) AS INTEGER) AS hour, action AS category, COUNT(*) AS count").
		Group("hour, category").
		Order("hour ASC, category ASC").
		Scan(&out).Error
	return out, err
}
