package handlers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// DnsEngineStatusData represents DNS engine status
type DnsEngineStatusData struct {
	Enabled          bool   `json:"enabled"`
	AcceptingQueries bool   `json:"accepting_queries"`
	LastError        string `json:"last_error"`
}

// ResponseDnsEngineStatus represents DNS engine status response
type ResponseDnsEngineStatus struct {
	Status string              `json:"status"`
	Data   DnsEngineStatusData `json:"data"`
	Error  *string             `json:"error"`
}

// Resolver represents an upstream DNS resolver
type Resolver struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Position int    `json:"position"`
}

// ResponseResolverList represents a list of resolvers response
type ResponseResolverList struct {
	Status string     `json:"status"`
	Data   []Resolver `json:"data"`
	Error  *string    `json:"error"`
}

// ResponseResolverSingle represents a single resolver response
type ResponseResolverSingle struct {
	Status string   `json:"status"`
	Data   Resolver `json:"data"`
	Error  *string  `json:"error"`
}

// CreateResolverRequest is the body for POST /dns/resolvers
type CreateResolverRequest struct {
	Name     string `json:"name"`
	Address  string `json:"address" binding:"required"`
	Protocol string `json:"protocol"`
}

// UpdateResolverRequest is the body for PUT/PATCH /dns/resolvers/:id.
// Fields are pointers so partial (PATCH-style) updates only touch supplied keys.
type UpdateResolverRequest struct {
	Name     *string `json:"name"`
	Address  *string `json:"address"`
	Protocol *string `json:"protocol"`
	Position *int    `json:"position"`
}

// ToggleDnsEngineRequest represents request to toggle DNS engine
type ToggleDnsEngineRequest struct {
	Enabled bool `json:"enabled"`
}

// GetDnsEngineStatus handles GET /dns/engine
func (h *APIHandler) GetDnsEngineStatus(c *gin.Context) {
	// 1. Fetch desired state from DB
	state, err := h.Store.SystemState.Get()
	if err != nil {
		errMsg := "failed to fetch desired DNS engine state"
		c.JSON(http.StatusInternalServerError, ResponseDnsEngineStatus{
			Status: "error",
			Data:   DnsEngineStatusData{},
			Error:  &errMsg,
		})
		return
	}

	// 2. Fetch actual state from dataplane
	status, err := h.DataPlaneClient.GetStatus()
	if err != nil {
		errMsg := "failed to fetch DNS engine runtime status"
		c.JSON(http.StatusBadGateway, ResponseDnsEngineStatus{
			Status: "error",
			Data:   DnsEngineStatusData{},
			Error:  &errMsg,
		})
		return
	}

	// 3. Combine intent + reality
	c.JSON(http.StatusOK, ResponseDnsEngineStatus{
		Status: "success",
		Data: DnsEngineStatusData{
			Enabled:          state.DNSEnabled,        // desired
			AcceptingQueries: status.AcceptingQueries, // actual
			LastError:        status.LastError,
		},
	})
}

// GetDnsMetrics handles GET /metrics
// It returns live DNS query performance metrics fetched from the dataplane.
func (h *APIHandler) GetDnsMetrics(c *gin.Context) {
	// 1. Fetch live metrics from dataplane
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	metrics, err := h.DataPlaneClient.GetLiveQueryMetrics(ctx)
	if err != nil {
		errMsg := "failed to fetch live DNS metrics from dataplane"
		c.JSON(http.StatusBadGateway, ResponseGeneric{
			Status: "error",
			Error:  &errMsg,
		})
		return
	}

	// 2. Compute derived values (interpretation only)
	var errorRate float64
	if metrics.TotalQueries > 0 {
		errorRate = float64(metrics.ErrorQueries) / float64(metrics.TotalQueries)
	}

	grade := gradeDnsPerformance(metrics.P95Ms, errorRate)

	// 3. Respond with observational data + interpretation
	c.JSON(http.StatusOK, ResponseGeneric{
		Status: "success",
		Data: map[string]interface{}{
			"window_seconds": metrics.WindowSizeSeconds,
			"queries": map[string]interface{}{
				"total":      metrics.TotalQueries,
				"errors":     metrics.ErrorQueries,
				"error_rate": errorRate,
			},
			"latency_ms": map[string]interface{}{
				"p50": metrics.P50Ms,
				"p95": metrics.P95Ms,
				"p99": metrics.P99Ms,
			},
			"grade": grade,
		},
	})
}

func gradeDnsPerformance(p95Ms uint64, errorRate float64) string {
	switch {
	case p95Ms < 20 && errorRate < 0.001:
		return "excellent"
	case p95Ms < 50 && errorRate < 0.01:
		return "good"
	case p95Ms < 100:
		return "degraded"
	case p95Ms >= 5000:
		return "unknown"
	default:
		return "bad"
	}
}

// ToggleDnsEngine handles POST /dns/engine
func (h *APIHandler) ToggleDnsEngine(c *gin.Context) {
	var req ToggleDnsEngineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseGeneric{
			Status: "error",
			Error:  &errMsg,
		})
		return
	}

	// 1. Persist desired state (source of truth)
	if err := h.Store.SystemState.SetDNSEnabled(req.Enabled); err != nil {
		errMsg := "failed to persist DNS engine state"
		c.JSON(http.StatusInternalServerError, ResponseGeneric{
			Status: "error",
			Error:  &errMsg,
		})
		return
	}

	// 2. Apply desired state to dataplane via gRPC
	if err := h.DataPlaneClient.SetAcceptQueries(req.Enabled); err != nil {
		errMsg := "failed to apply DNS engine state to dataplane"
		c.JSON(http.StatusBadGateway, ResponseGeneric{
			Status: "error",
			Error:  &errMsg,
		})
		return
	}

	// 3. Respond with acknowledged intent
	c.JSON(http.StatusOK, ResponseGeneric{
		Status: "success",
		Data: map[string]interface{}{
			"enabled": req.Enabled,
		},
	})
}

// resolverFromModel maps a stored resolver to its API representation.
func resolverFromModel(m models.Resolver) Resolver {
	return Resolver{
		ID:       m.ID,
		Name:     m.Name,
		Address:  m.Address,
		Protocol: m.Protocol,
		Position: m.Position,
	}
}

// validateResolverAddress ensures addr is a valid host:port pair.
func validateResolverAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: must be host:port", addr)
	}
	if host == "" {
		return fmt.Errorf("invalid address %q: host must not be empty", addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid address %q: port must be an integer in 1-65535", addr)
	}
	return nil
}

// normalizeProtocol validates and normalizes the transport protocol.
// Empty defaults to "udp".
func normalizeProtocol(p string) (string, error) {
	if p == "" {
		return "udp", nil
	}
	switch strings.ToLower(p) {
	case "udp", "tcp":
		return strings.ToLower(p), nil
	}
	return "", fmt.Errorf("invalid protocol %q: must be udp or tcp", p)
}

// applyResolvers pushes the persisted resolver set to the running dataplane
// via gRPC (mirrors ToggleDnsEngine's apply pattern). It returns an error the
// caller can surface as 502.
//
// When DataPlaneClient is nil (e.g. handler unit tests, or the dataplane is
// not wired), the change is persist-only and applied on the next dataplane
// start; this is treated as a successful no-op here.
func (h *APIHandler) applyResolvers() error {
	if h.DataPlaneClient == nil {
		return nil
	}
	addrs, err := h.Store.Resolvers.Addresses()
	if err != nil {
		return err
	}
	return h.DataPlaneClient.SetUpstreamResolvers(addrs)
}

// ListResolvers handles GET /dns/resolvers
// Returns the persisted, editable upstream resolver set.
func (h *APIHandler) ListResolvers(c *gin.Context) {
	list, err := h.Store.Resolvers.List()
	if err != nil {
		errMsg := "failed to fetch resolvers"
		c.JSON(http.StatusInternalServerError, ResponseResolverList{Status: "error", Error: &errMsg})
		return
	}

	resolvers := make([]Resolver, 0, len(list))
	for _, m := range list {
		resolvers = append(resolvers, resolverFromModel(m))
	}
	c.JSON(http.StatusOK, ResponseResolverList{
		Status: "success",
		Data:   resolvers,
	})
}

// CreateResolver handles POST /dns/resolvers
func (h *APIHandler) CreateResolver(c *gin.Context) {
	var req CreateResolverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	if err := validateResolverAddress(req.Address); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	protocol, err := normalizeProtocol(req.Protocol)
	if err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	name := req.Name
	if name == "" {
		name = req.Address
	}

	position, err := h.Store.Resolvers.NextPosition()
	if err != nil {
		errMsg := "failed to determine resolver position"
		c.JSON(http.StatusInternalServerError, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	m := &models.Resolver{
		ID:       uuid.New().String(),
		Name:     name,
		Address:  req.Address,
		Protocol: protocol,
		Position: position,
	}
	if err := h.Store.Resolvers.Create(m); err != nil {
		errMsg := "failed to create resolver"
		c.JSON(http.StatusInternalServerError, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	// Apply the new set to the running dataplane.
	if err := h.applyResolvers(); err != nil {
		errMsg := "resolver persisted but failed to apply to dataplane"
		c.JSON(http.StatusBadGateway, ResponseResolverSingle{Status: "error", Data: resolverFromModel(*m), Error: &errMsg})
		return
	}

	c.JSON(http.StatusCreated, ResponseResolverSingle{
		Status: "success",
		Data:   resolverFromModel(*m),
	})
}

// UpdateResolver handles PUT/PATCH /dns/resolvers/:id (edit fields / reorder).
func (h *APIHandler) UpdateResolver(c *gin.Context) {
	existing, err := h.Store.Resolvers.Get(c.Param("id"))
	if err != nil {
		errMsg := "resolver not found"
		c.JSON(http.StatusNotFound, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	var req UpdateResolverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Address != nil {
		if err := validateResolverAddress(*req.Address); err != nil {
			errMsg := err.Error()
			c.JSON(http.StatusBadRequest, ResponseResolverSingle{Status: "error", Error: &errMsg})
			return
		}
		existing.Address = *req.Address
	}
	if req.Protocol != nil {
		protocol, err := normalizeProtocol(*req.Protocol)
		if err != nil {
			errMsg := err.Error()
			c.JSON(http.StatusBadRequest, ResponseResolverSingle{Status: "error", Error: &errMsg})
			return
		}
		existing.Protocol = protocol
	}
	if req.Position != nil {
		existing.Position = *req.Position
	}

	if err := h.Store.Resolvers.Update(existing); err != nil {
		errMsg := "failed to update resolver"
		c.JSON(http.StatusInternalServerError, ResponseResolverSingle{Status: "error", Error: &errMsg})
		return
	}

	if err := h.applyResolvers(); err != nil {
		errMsg := "resolver updated but failed to apply to dataplane"
		c.JSON(http.StatusBadGateway, ResponseResolverSingle{Status: "error", Data: resolverFromModel(*existing), Error: &errMsg})
		return
	}

	c.JSON(http.StatusOK, ResponseResolverSingle{
		Status: "success",
		Data:   resolverFromModel(*existing),
	})
}

// DeleteResolver handles DELETE /dns/resolvers/:id
func (h *APIHandler) DeleteResolver(c *gin.Context) {
	if err := h.Store.Resolvers.Delete(c.Param("id")); err != nil {
		errMsg := "resolver not found"
		c.JSON(http.StatusNotFound, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	if err := h.applyResolvers(); err != nil {
		errMsg := "resolver deleted but failed to apply to dataplane"
		c.JSON(http.StatusBadGateway, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	c.JSON(http.StatusOK, ResponseGeneric{Status: "success", Data: map[string]interface{}{}})
}
