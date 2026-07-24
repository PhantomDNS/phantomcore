// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lopster568/phantomDNS/internal/report"
)

// parseReportTime accepts either an RFC3339 timestamp or a plain YYYY-MM-DD
// date. Dates are interpreted in UTC.
func parseReportTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// GetReport handles GET /api/v1/reports?from=&to=&format=text|html
//
// It generates a plain-language period report from the DNS query log. When
// from/to are omitted it defaults to the last 7 days. format defaults to text;
// pass format=html for the HTML rendering.
func (h *APIHandler) GetReport(c *gin.Context) {
	now := time.Now().UTC()
	to := now
	from := now.AddDate(0, 0, -7)

	if v, ok := parseReportTime(c.Query("from")); ok {
		from = v
	}
	if v, ok := parseReportTime(c.Query("to")); ok {
		to = v
	}
	if to.Before(from) {
		errMsg := "invalid range: 'to' is before 'from'"
		c.JSON(http.StatusBadRequest, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	rep, err := report.Generate(h.Store.QueryLogs, from, to)
	if err != nil {
		errMsg := "failed to generate report"
		c.JSON(http.StatusInternalServerError, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	switch c.Query("format") {
	case "html":
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(report.RenderHTML(rep)))
	case "json":
		c.JSON(http.StatusOK, ResponseGeneric{Status: "success", Data: rep})
	default:
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(report.RenderText(rep)))
	}
}
