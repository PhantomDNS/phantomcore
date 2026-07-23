package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type DashboardSummaryData struct {
	TotalQueries      uint64  `json:"total_queries"`
	BlockedQueries    uint64  `json:"blocked_queries"`
	AllowedQueries    uint64  `json:"allowed_queries"`
	RedirectedQueries uint64  `json:"redirected_queries"`
	BlockRatePercent  float64 `json:"block_rate_percent"`
}

type ResponseDashboardSummary struct {
	Status string               `json:"status"`
	Data   DashboardSummaryData `json:"data"`
	Error  *string              `json:"error"`
}

// GetDashboardSummary handles GET /dashboard/summary
func (h *APIHandler) GetDashboardSummary(c *gin.Context) {
	stats, err := h.Store.Statistics.ListRecent(1)
	if err != nil || len(stats) == 0 {
		// Return zeros if no stats yet
		c.JSON(http.StatusOK, ResponseDashboardSummary{
			Status: "success",
			Data:   DashboardSummaryData{},
		})
		return
	}

	s := stats[0]
	var blockRate float64
	if s.TotalQueries > 0 {
		blockRate = float64(s.BlockedQueries) / float64(s.TotalQueries) * 100
	}

	c.JSON(http.StatusOK, ResponseDashboardSummary{
		Status: "success",
		Data: DashboardSummaryData{
			TotalQueries:      s.TotalQueries,
			BlockedQueries:    s.BlockedQueries,
			AllowedQueries:    s.AllowedQueries,
			RedirectedQueries: s.RedirectedQueries,
			BlockRatePercent:  blockRate,
		},
	})
}
