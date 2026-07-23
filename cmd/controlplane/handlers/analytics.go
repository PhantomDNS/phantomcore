package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

type QueryLogEntry struct {
	ID              uint      `json:"id"`
	Domain          string    `json:"domain"`
	ClientIP        string    `json:"client_ip"`
	Action          string    `json:"action"`
	Timestamp       time.Time `json:"timestamp"`
	IsSuspicious    bool      `json:"is_suspicious"`
	ThreatScore     float64   `json:"threat_score"`
	DetectionMethod string    `json:"detection_method,omitempty"`
	ThreatReason    string    `json:"threat_reason,omitempty"`
}

type AnalyticsSummaryData struct {
	TotalQueries     uint64  `json:"total_queries"`
	BlockedQueries   uint64  `json:"blocked_queries"`
	AllowedQueries   uint64  `json:"allowed_queries"`
	BlockRatePercent float64 `json:"block_rate_percent"`
}

type ResponseAnalyticsSummary struct {
	Status string               `json:"status"`
	Data   AnalyticsSummaryData `json:"data"`
	Error  *string              `json:"error"`
}

type ResponseQueryLogList struct {
	Status string          `json:"status"`
	Data   []QueryLogEntry `json:"data"`
	Error  *string         `json:"error"`
}

// GetAnalyticsSummary handles GET /analytics/summary
func (h *APIHandler) GetAnalyticsSummary(c *gin.Context) {
	stats, err := h.Store.Statistics.ListRecent(1)
	if err != nil || len(stats) == 0 {
		c.JSON(http.StatusOK, ResponseAnalyticsSummary{
			Status: "success",
			Data:   AnalyticsSummaryData{},
		})
		return
	}

	s := stats[0]
	var blockRate float64
	if s.TotalQueries > 0 {
		blockRate = float64(s.BlockedQueries) / float64(s.TotalQueries) * 100
	}

	c.JSON(http.StatusOK, ResponseAnalyticsSummary{
		Status: "success",
		Data: AnalyticsSummaryData{
			TotalQueries:     s.TotalQueries,
			BlockedQueries:   s.BlockedQueries,
			AllowedQueries:   s.AllowedQueries,
			BlockRatePercent: blockRate,
		},
	})
}

// GetAuditLogs handles GET /analytics/audits
// Returns recent DNS query logs as the audit trail.
func (h *APIHandler) GetAuditLogs(c *gin.Context) {
	queries, err := h.Store.QueryLogs.ListRecent(100)
	if err != nil {
		errMsg := "failed to fetch query logs"
		c.JSON(http.StatusInternalServerError, ResponseQueryLogList{Status: "error", Error: &errMsg})
		return
	}

	entries := make([]QueryLogEntry, 0, len(queries))
	for _, q := range queries {
		entries = append(entries, toQueryLogEntry(q))
	}

	c.JSON(http.StatusOK, ResponseQueryLogList{
		Status: "success",
		Data:   entries,
	})
}

// QueryLogPageInfo carries paging metadata alongside a page of query logs.
type QueryLogPageInfo struct {
	Total   int64 `json:"total"`    // total rows matching the filter (ignoring paging)
	Limit   int   `json:"limit"`    // effective page size after clamping
	Offset  int   `json:"offset"`   // rows skipped
	HasMore bool  `json:"has_more"` // whether more rows exist beyond this page
}

// QueryLogListData is the paginated payload for GetQueryLogs.
type QueryLogListData struct {
	Items    []QueryLogEntry  `json:"items"`
	PageInfo QueryLogPageInfo `json:"page_info"`
}

// ResponseQueryLogPage is the envelope for a paginated query-log listing.
type ResponseQueryLogPage struct {
	Status string           `json:"status"`
	Data   QueryLogListData `json:"data"`
	Error  *string          `json:"error"`
}

// toQueryLogEntry maps a stored DNSQuery row to its API representation.
func toQueryLogEntry(q models.DNSQuery) QueryLogEntry {
	return QueryLogEntry{
		ID:              q.ID,
		Domain:          q.Domain,
		ClientIP:        q.ClientIP,
		Action:          q.Action,
		Timestamp:       q.Timestamp,
		IsSuspicious:    q.IsSuspicious,
		ThreatScore:     q.ThreatScore,
		DetectionMethod: q.DetectionMethod,
		ThreatReason:    q.ThreatReason,
	}
}

func isValidQueryLogAction(a string) bool {
	switch a {
	case "block", "allow", "flagged", "redirect":
		return true
	default:
		return false
	}
}

// GetQueryLogs handles GET /analytics/logs
// Returns a server-side paginated, filterable page of DNS query logs.
//
// Query params (all optional):
//
//	limit      page size (default 50, max 200)
//	offset     rows to skip (default 0)
//	client_ip  exact client IP match
//	action     one of block | allow | flagged | redirect
//	domain     case-insensitive substring match on the queried domain
//	suspicious boolean; when true, only suspicious rows
//	from, to   RFC3339 timestamps bounding the result window (inclusive)
func (h *APIHandler) GetQueryLogs(c *gin.Context) {
	badRequest := func(msg string) {
		c.JSON(http.StatusBadRequest, ResponseGeneric{Status: "error", Error: &msg})
	}

	filter := repositories.QueryLogFilter{
		ClientIP: strings.TrimSpace(c.Query("client_ip")),
		Domain:   strings.TrimSpace(c.Query("domain")),
	}

	// limit
	limit := repositories.DefaultQueryLogPageSize
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			badRequest("invalid 'limit': must be a positive integer")
			return
		}
		limit = n
	}
	limit = repositories.ClampQueryLogPageSize(limit)
	filter.Limit = limit

	// offset
	offset := 0
	if v := c.Query("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			badRequest("invalid 'offset': must be a non-negative integer")
			return
		}
		offset = n
	}
	filter.Offset = offset

	// action
	if v := strings.TrimSpace(c.Query("action")); v != "" {
		if !isValidQueryLogAction(v) {
			badRequest("invalid 'action': must be one of block, allow, flagged, redirect")
			return
		}
		filter.Action = v
	}

	// suspicious
	if v := c.Query("suspicious"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			badRequest("invalid 'suspicious': must be a boolean")
			return
		}
		filter.SuspiciousOnly = b
	}

	// time range
	if v := c.Query("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			badRequest("invalid 'from': must be an RFC3339 timestamp")
			return
		}
		filter.From = &t
	}
	if v := c.Query("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			badRequest("invalid 'to': must be an RFC3339 timestamp")
			return
		}
		filter.To = &t
	}

	queries, total, err := h.Store.QueryLogs.List(filter)
	if err != nil {
		errMsg := "failed to fetch query logs"
		c.JSON(http.StatusInternalServerError, ResponseQueryLogPage{Status: "error", Error: &errMsg})
		return
	}

	items := make([]QueryLogEntry, 0, len(queries))
	for _, q := range queries {
		items = append(items, toQueryLogEntry(q))
	}

	c.JSON(http.StatusOK, ResponseQueryLogPage{
		Status: "success",
		Data: QueryLogListData{
			Items: items,
			PageInfo: QueryLogPageInfo{
				Total:   total,
				Limit:   limit,
				Offset:  offset,
				HasMore: int64(offset+len(items)) < total,
			},
		},
	})
}
