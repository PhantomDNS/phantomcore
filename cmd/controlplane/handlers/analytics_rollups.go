// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

// RollupWindowInfo echoes the effective window the rollups were computed over,
// so a client can render the range and paging it actually got.
type RollupWindowInfo struct {
	From     *time.Time `json:"from"`
	To       *time.Time `json:"to"`
	TopN     int        `json:"top_n"`
	ClientIP string     `json:"client_ip,omitempty"`
}

// AnalyticsRollupsData is the payload of GetAnalyticsRollups. The nested slices
// reuse the repository aggregate structs directly (they already carry JSON
// tags). ClientTimeline is populated only when a client_ip is supplied; Anomaly
// is populated only when a full [from, to] window is given (it is compared
// against the immediately preceding window of equal length).
type AnalyticsRollupsData struct {
	Window     RollupWindowInfo              `json:"window"`
	TopClients []repositories.ClientActivity `json:"top_clients"`
	TopBlocked []repositories.DomainCount    `json:"top_blocked_domains"`
	Categories []repositories.CategoryCount  `json:"categories"`
	Timeline   []repositories.TimeBucket     `json:"client_timeline"`
	Heatmap    []repositories.HeatmapCell    `json:"heatmap"`
	Anomaly    *repositories.AnomalyDigest   `json:"anomaly,omitempty"`
}

// ResponseAnalyticsRollups is the standard envelope for the rollups endpoint.
type ResponseAnalyticsRollups struct {
	Status string               `json:"status"`
	Data   AnalyticsRollupsData `json:"data"`
	Error  *string              `json:"error"`
}

// GetAnalyticsRollups handles GET /analytics/rollups.
//
// It returns aggregate rollups over the DNS query log: a top-clients
// leaderboard, top blocked domains, a per-disposition category breakdown, a
// category x hour-of-day heatmap, an optional per-client activity timeline, and
// an optional anomaly digest comparing the window against the one before it.
//
// Query params (all optional):
//
//	from, to   RFC3339 timestamps bounding the window (inclusive)
//	top        leaderboard size (default 10, max 100)
//	client_ip  when set, includes that client's hour-bucketed timeline
func (h *APIHandler) GetAnalyticsRollups(c *gin.Context) {
	badRequest := func(msg string) {
		c.JSON(http.StatusBadRequest, ResponseGeneric{Status: "error", Error: &msg})
	}

	var window repositories.AnalyticsWindow

	if v := c.Query("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			badRequest("invalid 'from': must be an RFC3339 timestamp")
			return
		}
		window.From = &t
	}
	if v := c.Query("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			badRequest("invalid 'to': must be an RFC3339 timestamp")
			return
		}
		window.To = &t
	}
	if window.From != nil && window.To != nil && window.To.Before(*window.From) {
		badRequest("invalid range: 'to' must not be before 'from'")
		return
	}

	topN := repositories.DefaultAnalyticsTopN
	if v := c.Query("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			badRequest("invalid 'top': must be a positive integer")
			return
		}
		topN = n
	}
	topN = repositories.ClampAnalyticsTopN(topN)
	window.Limit = topN

	clientIP := strings.TrimSpace(c.Query("client_ip"))

	fail := func() {
		errMsg := "failed to compute analytics rollups"
		c.JSON(http.StatusInternalServerError, ResponseAnalyticsRollups{Status: "error", Error: &errMsg})
	}

	topClients, err := h.Store.QueryLogs.TopClients(window)
	if err != nil {
		fail()
		return
	}
	topBlocked, err := h.Store.QueryLogs.TopBlockedDomains(window)
	if err != nil {
		fail()
		return
	}
	categories, err := h.Store.QueryLogs.CategoryBreakdown(window)
	if err != nil {
		fail()
		return
	}
	heatmap, err := h.Store.QueryLogs.CategoryHourHeatmap(window)
	if err != nil {
		fail()
		return
	}

	timeline := []repositories.TimeBucket{}
	if clientIP != "" {
		timeline, err = h.Store.QueryLogs.ClientTimeline(clientIP, window)
		if err != nil {
			fail()
			return
		}
	}

	var anomaly *repositories.AnomalyDigest
	if window.From != nil && window.To != nil {
		if digest, ok := h.computeAnomaly(window); ok {
			anomaly = digest
		} else {
			fail()
			return
		}
	}

	c.JSON(http.StatusOK, ResponseAnalyticsRollups{
		Status: "success",
		Data: AnalyticsRollupsData{
			Window: RollupWindowInfo{
				From:     window.From,
				To:       window.To,
				TopN:     topN,
				ClientIP: clientIP,
			},
			TopClients: topClients,
			TopBlocked: topBlocked,
			Categories: categories,
			Timeline:   timeline,
			Heatmap:    heatmap,
			Anomaly:    anomaly,
		},
	})
}

// computeAnomaly compares the given window against the immediately preceding
// window of equal length and returns the digest. It returns ok=false only on a
// repository error. The caller guarantees both bounds are set.
func (h *APIHandler) computeAnomaly(current repositories.AnalyticsWindow) (*repositories.AnomalyDigest, bool) {
	dur := current.To.Sub(*current.From)
	priorFrom := current.From.Add(-dur)
	// The window's To bound is inclusive, so end the prior window one tick
	// before the current window starts to avoid double-counting a row that sits
	// exactly on the shared boundary.
	priorTo := current.From.Add(-time.Nanosecond)
	prior := repositories.AnalyticsWindow{
		From:  &priorFrom,
		To:    &priorTo,
		Limit: current.Limit,
	}
	digest, err := h.Store.QueryLogs.AnomalyDigestBetween(current, prior, repositories.AnomalyThresholds{})
	if err != nil {
		return nil, false
	}
	return &digest, true
}
