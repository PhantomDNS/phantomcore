package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/fleet"
)

// ResponseFleet is the consolidated fleet view response.
type ResponseFleet struct {
	Status string          `json:"status"`
	Data   fleet.FleetView `json:"data"`
	Error  *string         `json:"error"`
}

// PostFleetHeartbeat handles POST /fleet/heartbeat.
//
// A reporting box submits aggregate metadata (no query contents). The route is
// authenticated with the dedicated fleet heartbeat token, not the admin key.
func (h *APIHandler) PostFleetHeartbeat(c *gin.Context) {
	if h.Fleet == nil {
		errMsg := "fleet aggregator disabled"
		c.JSON(http.StatusServiceUnavailable, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	var hb fleet.Heartbeat
	if err := c.ShouldBindJSON(&hb); err != nil {
		errMsg := "invalid heartbeat payload — site_id is required"
		c.JSON(http.StatusBadRequest, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	h.Fleet.Record(hb)
	c.JSON(http.StatusOK, ResponseGeneric{
		Status: "success",
		Data:   gin.H{"site_id": hb.SiteID, "accepted": true},
	})
}

// GetFleet handles GET /fleet — the consolidated, read-only fleet view. This
// route is admin-only (gated by the global auth middleware).
func (h *APIHandler) GetFleet(c *gin.Context) {
	if h.Fleet == nil {
		errMsg := "fleet aggregator disabled"
		c.JSON(http.StatusServiceUnavailable, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	c.JSON(http.StatusOK, ResponseFleet{
		Status: "success",
		Data:   h.Fleet.Snapshot(),
	})
}
