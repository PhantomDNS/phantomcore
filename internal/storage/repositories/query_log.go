// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/report"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
)

// Page-size bounds for paginated query-log reads.
const (
	// DefaultQueryLogPageSize is used when no (or an invalid) limit is supplied.
	DefaultQueryLogPageSize = 50
	// MaxQueryLogPageSize caps how many rows a single page may return so a
	// caller cannot ask the database for an unbounded result set.
	MaxQueryLogPageSize = 200
)

// QueryLogFilter describes the optional filters and paging window for a
// server-side query-log listing. Zero-value fields mean "no filter".
type QueryLogFilter struct {
	ClientIP       string     // exact match (indexed column)
	Action         string     // exact match: allow | block | flagged | redirect
	Domain         string     // case-insensitive substring match
	SuspiciousOnly bool       // when true, only rows with IsSuspicious = true
	From           *time.Time // inclusive lower bound on Timestamp
	To             *time.Time // inclusive upper bound on Timestamp
	Limit          int        // page size (clamped to [1, MaxQueryLogPageSize])
	Offset         int        // rows to skip (negative treated as 0)
}

// ClampQueryLogPageSize normalizes a requested page size into the allowed
// bounds. Non-positive values fall back to the default; values above the cap
// are clamped to MaxQueryLogPageSize.
func ClampQueryLogPageSize(limit int) int {
	if limit <= 0 {
		return DefaultQueryLogPageSize
	}
	if limit > MaxQueryLogPageSize {
		return MaxQueryLogPageSize
	}
	return limit
}

// Interface (clean, mockable)
type QueryLogRepository interface {
	Save(query *models.DNSQuery) error
	ListRecent(limit int) ([]models.DNSQuery, error)
	// List returns a filtered, paginated page of query logs ordered
	// newest-first, along with the total number of rows matching the filter
	// (ignoring the paging window) so callers can render page info.
	List(filter QueryLogFilter) ([]models.DNSQuery, int64, error)

	// Analytics rollups over the query log. Each is an indexed, bounded
	// aggregate scoped to an optional time window (see analytics.go).
	TopClients(w AnalyticsWindow) ([]ClientActivity, error)
	TopBlockedDomains(w AnalyticsWindow) ([]DomainCount, error)
	CategoryBreakdown(w AnalyticsWindow) ([]CategoryCount, error)
	ClientTimeline(clientIP string, w AnalyticsWindow) ([]TimeBucket, error)
	CategoryHourHeatmap(w AnalyticsWindow) ([]HeatmapCell, error)

	// GatherWindowStats and AnomalyDigestBetween back the anomaly digest
	// (see anomaly.go). AnomalyDigestBetween compares a current and a prior
	// window; delivery of the resulting digest is handled elsewhere.
	GatherWindowStats(w AnalyticsWindow) (WindowStats, error)
	AnomalyDigestBetween(current, prior AnalyticsWindow, cfg AnomalyThresholds) (AnomalyDigest, error)

	// Aggregate computes period aggregates for the reporting engine. It
	// satisfies report.Aggregator.
	Aggregate(from, to time.Time, topN int) (report.Aggregates, error)

	// Count returns the total number of rows in the query log table.
	Count() (int64, error)
	// DeleteOlderThan removes rows with a timestamp before cutoff and
	// returns the number of rows deleted.
	DeleteOlderThan(cutoff time.Time) (int64, error)
	// EnforceRowCap keeps at most maxRows of the newest rows, deleting the
	// oldest beyond that, and returns the number of rows deleted. maxRows
	// <= 0 disables enforcement (no-op).
	EnforceRowCap(maxRows int64) (int64, error)
}

// Implementation
type GormQueryLogRepo struct {
	db *gorm.DB
}

func NewGormQueryLogRepo(db *gorm.DB) *GormQueryLogRepo {
	return &GormQueryLogRepo{db: db}
}

func (r *GormQueryLogRepo) Save(query *models.DNSQuery) error {
	query.Timestamp = time.Now()
	logger.Log.Debug("Saving DNS query log")
	logger.Log.Debug("query", query)
	return r.db.Create(query).Error
}

func (r *GormQueryLogRepo) ListRecent(limit int) ([]models.DNSQuery, error) {
	var queries []models.DNSQuery
	err := r.db.Order("timestamp desc").Limit(limit).Find(&queries).Error
	return queries, err
}

// List applies the given filters and returns one page of results plus the
// total match count. Equality filters (client IP, action, timestamp range,
// suspicious) use indexed columns; the domain filter is a substring LIKE which
// necessarily scans, so it is applied last and only when requested.
func (r *GormQueryLogRepo) List(filter QueryLogFilter) ([]models.DNSQuery, int64, error) {
	limit := ClampQueryLogPageSize(filter.Limit)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build the shared WHERE clause once; reuse for both count and page.
	q := r.db.Model(&models.DNSQuery{})
	if filter.ClientIP != "" {
		q = q.Where("client_ip = ?", filter.ClientIP)
	}
	if filter.Action != "" {
		q = q.Where("action = ?", filter.Action)
	}
	if filter.SuspiciousOnly {
		q = q.Where("is_suspicious = ?", true)
	}
	if filter.From != nil {
		q = q.Where("timestamp >= ?", *filter.From)
	}
	if filter.To != nil {
		q = q.Where("timestamp <= ?", *filter.To)
	}
	if filter.Domain != "" {
		q = q.Where("domain LIKE ?", "%"+filter.Domain+"%")
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var queries []models.DNSQuery
	err := q.Order("timestamp desc").Limit(limit).Offset(offset).Find(&queries).Error
	return queries, total, err
}

// Count returns the number of rows in the query log table.
func (r *GormQueryLogRepo) Count() (int64, error) {
	var n int64
	err := r.db.Model(&models.DNSQuery{}).Count(&n).Error
	return n, err
}

// DeleteOlderThan removes query logs with a timestamp before cutoff and
// returns the number of rows deleted. Timestamp is indexed, so this is a
// ranged delete, not a full scan.
func (r *GormQueryLogRepo) DeleteOlderThan(cutoff time.Time) (int64, error) {
	res := r.db.Where("timestamp < ?", cutoff).Delete(&models.DNSQuery{})
	return res.RowsAffected, res.Error
}

// EnforceRowCap keeps at most maxRows of the newest query logs, deleting the
// oldest beyond that. This is disk insurance: a sustained query rate can
// exceed any time-window estimate, and the underlying storage (e.g. a Pi's
// SD card) must not fill. IDs are monotonic, so "newest" == "highest id".
// Returns the number of rows deleted.
func (r *GormQueryLogRepo) EnforceRowCap(maxRows int64) (int64, error) {
	if maxRows <= 0 {
		return 0, nil
	}
	// Find the id of the maxRows-th newest row; everything with a smaller
	// id is surplus. OFFSET maxRows-1 lands on the last row we keep.
	var threshold uint
	err := r.db.Model(&models.DNSQuery{}).
		Order("id desc").
		Offset(int(maxRows - 1)).
		Limit(1).
		Pluck("id", &threshold).Error
	if err != nil {
		return 0, err
	}
	if threshold == 0 {
		// Fewer than maxRows rows present; nothing to trim.
		return 0, nil
	}
	res := r.db.Where("id < ?", threshold).Delete(&models.DNSQuery{})
	return res.RowsAffected, res.Error
}
