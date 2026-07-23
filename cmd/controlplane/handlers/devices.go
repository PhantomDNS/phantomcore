// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/inventory"
)

type ResponseDevices struct {
	Status string             `json:"status"`
	Data   []inventory.Device `json:"data"`
	Error  *string            `json:"error"`
}

// GetDevices handles GET /api/v1/devices, returning the passive LAN device
// inventory. When the inventory feature is disabled (nil), an empty list is
// returned so clients get a stable shape.
func (h *APIHandler) GetDevices(c *gin.Context) {
	devices := []inventory.Device{}
	if h.Inventory != nil {
		devices = h.Inventory.Devices()
	}
	c.JSON(http.StatusOK, ResponseDevices{
		Status: "success",
		Data:   devices,
	})
}
