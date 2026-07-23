package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"gorm.io/gorm"
)

// Policy represents a policy in API responses
type Policy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Action      string   `json:"action"`
	RedirectIP  string   `json:"redirect_ip,omitempty"`
	Domains     []string `json:"domains"`
	Regexes     []string `json:"regexes"`
	// ClientCIDRs scopes the policy to specific clients by IP/CIDR (I-014).
	// Empty means the policy applies to all clients.
	ClientCIDRs []string `json:"client_cidrs"`
	Priority    int      `json:"priority"`
	Enabled     bool     `json:"enabled"`

	// Optional schedule (I-038). Empty fields mean the policy is always active.
	ScheduleDays []string `json:"schedule_days,omitempty"`
	StartTime    string   `json:"start_time,omitempty"`
	EndTime      string   `json:"end_time,omitempty"`
	Timezone     string   `json:"timezone,omitempty"`
}

type PolicyListData struct {
	TotalPolicies    int      `json:"total_policies"`
	ActivePolicies   int      `json:"active_policies"`
	InactivePolicies int      `json:"inactive_policies"`
	List             []Policy `json:"list"`
}

type ResponsePolicyList struct {
	Status string         `json:"status"`
	Data   PolicyListData `json:"data"`
	Error  *string        `json:"error"`
}

type ResponsePolicySingle struct {
	Status string  `json:"status"`
	Data   Policy  `json:"data"`
	Error  *string `json:"error"`
}

type CreatePolicyRequest struct {
	ID          string   `json:"id" binding:"required"`
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Action      string   `json:"action" binding:"required"`
	RedirectIP  string   `json:"redirect_ip"`
	Domains     []string `json:"domains" binding:"required"`
	Regexes     []string `json:"regexes"`
	// ClientCIDRs optionally scopes the policy to specific clients (I-014).
	ClientCIDRs []string `json:"client_cidrs"`
	Priority    int      `json:"priority"`

	// Optional schedule (I-038). Omit for an always-on policy.
	ScheduleDays []string `json:"schedule_days"`
	StartTime    string   `json:"start_time"`
	EndTime      string   `json:"end_time"`
	Timezone     string   `json:"timezone"`
}

// UpdatePolicyRequest carries an edit. Every field is a pointer so a nil value
// means "leave unchanged" — this lets a single handler serve both PUT (full
// replace, client sends every field) and PATCH (partial edit, client sends a
// subset). This is the inline-edit path (I-004).
type UpdatePolicyRequest struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Category    *string   `json:"category"`
	Action      *string   `json:"action"`
	RedirectIP  *string   `json:"redirect_ip"`
	Domains     *[]string `json:"domains"`
	Regexes     *[]string `json:"regexes"`
	// ClientCIDRs edits the client scope; nil leaves it unchanged, an empty
	// slice clears it (policy becomes unscoped) (I-014).
	ClientCIDRs *[]string `json:"client_cidrs"`
	Priority    *int      `json:"priority"`
	Enabled     *bool     `json:"enabled"`

	// Optional schedule (I-038). Pointers keep PATCH semantics: nil = unchanged.
	// Send an empty value (e.g. "" / []) to clear a field back to always-on.
	ScheduleDays *[]string `json:"schedule_days"`
	StartTime    *string   `json:"start_time"`
	EndTime      *string   `json:"end_time"`
	Timezone     *string   `json:"timezone"`
}

func policyFromModel(m models.Policy) Policy {
	var domains, regexes, scheduleDays, clientCIDRs []string
	if m.Domains != "" {
		_ = json.Unmarshal([]byte(m.Domains), &domains)
	}
	if m.Regexes != "" {
		_ = json.Unmarshal([]byte(m.Regexes), &regexes)
	}
	if m.ScheduleDays != "" {
		_ = json.Unmarshal([]byte(m.ScheduleDays), &scheduleDays)
	}
	if m.ClientCIDRs != "" {
		_ = json.Unmarshal([]byte(m.ClientCIDRs), &clientCIDRs)
	}
	return Policy{
		ID:           m.ID,
		Name:         m.Name,
		Description:  m.Description,
		Category:     m.Category,
		Action:       m.Action,
		RedirectIP:   m.RedirectIP,
		Domains:      domains,
		Regexes:      regexes,
		ClientCIDRs:  clientCIDRs,
		Priority:     m.Priority,
		Enabled:      m.Enabled,
		ScheduleDays: scheduleDays,
		StartTime:    m.ScheduleStart,
		EndTime:      m.ScheduleEnd,
		Timezone:     m.Timezone,
	}
}

// scheduleDaysJSON encodes the day-of-week list as JSON text for storage,
// returning "" for an empty list so the column stays clean and the policy reads
// back as always-on (I-038).
func scheduleDaysJSON(days []string) string {
	if len(days) == 0 {
		return ""
	}
	b, _ := json.Marshal(days)
	return string(b)
}

// reloadPolicyEngine rebuilds the in-process policy snapshot from storage so
// mutations take effect immediately. It is best-effort and nil-safe: storage
// is the source of truth, and the dataplane also reloads from the same DB on
// its own schedule, so a transient failure here never loses a change.
func (h *APIHandler) reloadPolicyEngine() {
	if h.PolicyEngine == nil {
		return
	}
	stored, err := h.Store.Policies.List()
	if err != nil {
		return
	}
	engPolicies := make([]policy.Policy, 0, len(stored))
	for _, m := range stored {
		engPolicies = append(engPolicies, repositories.ToEnginePolicy(m))
	}
	_ = h.PolicyEngine.LoadPolicies(engPolicies)
}

// ListPolicies handles GET /policies
func (h *APIHandler) ListPolicies(c *gin.Context) {
	stored, err := h.Store.Policies.List()
	if err != nil {
		errMsg := "failed to fetch policies"
		c.JSON(http.StatusInternalServerError, ResponsePolicyList{Status: "error", Error: &errMsg})
		return
	}

	list := make([]Policy, 0, len(stored))
	activeCount := 0
	for _, m := range stored {
		p := policyFromModel(m)
		list = append(list, p)
		if p.Enabled {
			activeCount++
		}
	}

	c.JSON(http.StatusOK, ResponsePolicyList{
		Status: "success",
		Data: PolicyListData{
			TotalPolicies:    len(list),
			ActivePolicies:   activeCount,
			InactivePolicies: len(list) - activeCount,
			List:             list,
		},
	})
}

// GetPolicy handles GET /policies/:id
func (h *APIHandler) GetPolicy(c *gin.Context) {
	m, err := h.Store.Policies.GetByID(c.Param("id"))
	if err != nil {
		errMsg := "policy not found"
		c.JSON(http.StatusNotFound, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}
	c.JSON(http.StatusOK, ResponsePolicySingle{
		Status: "success",
		Data:   policyFromModel(*m),
	})
}

// CreatePolicy handles POST /policies
func (h *APIHandler) CreatePolicy(c *gin.Context) {
	var req CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}

	domainsJSON, _ := json.Marshal(req.Domains)
	regexesJSON, _ := json.Marshal(req.Regexes)
	clientCIDRsJSON, _ := json.Marshal(req.ClientCIDRs)

	m := &models.Policy{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Category:    req.Category,
		Action:      req.Action,
		RedirectIP:  req.RedirectIP,
		Domains:     string(domainsJSON),
		Regexes:     string(regexesJSON),
		ClientCIDRs: string(clientCIDRsJSON),
		Priority:    req.Priority,
		Enabled:     true,

		ScheduleDays:  scheduleDaysJSON(req.ScheduleDays),
		ScheduleStart: req.StartTime,
		ScheduleEnd:   req.EndTime,
		Timezone:      req.Timezone,
	}

	// Validate against the same rules the engine enforces (action enum, etc.)
	// so we never persist a policy the engine would reject.
	ep := repositories.ToEnginePolicy(*m)
	if err := policy.ValidatePolicy(&ep); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}

	if err := h.Store.Policies.Create(m); err != nil {
		errMsg := "failed to create policy"
		c.JSON(http.StatusInternalServerError, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}

	// Persisted — now apply to the running engine snapshot.
	h.reloadPolicyEngine()

	c.JSON(http.StatusCreated, ResponsePolicySingle{
		Status: "success",
		Data:   policyFromModel(*m),
	})
}

// UpdatePolicy handles PUT /policies/:id and PATCH /policies/:id.
// It loads the existing policy, applies only the fields present in the request,
// re-validates, persists, and reloads the engine. This is the inline-edit
// feature (I-004).
func (h *APIHandler) UpdatePolicy(c *gin.Context) {
	m, err := h.Store.Policies.GetByID(c.Param("id"))
	if err != nil {
		errMsg := "policy not found"
		c.JSON(http.StatusNotFound, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}

	var req UpdatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}

	if req.Name != nil {
		m.Name = *req.Name
	}
	if req.Description != nil {
		m.Description = *req.Description
	}
	if req.Category != nil {
		m.Category = *req.Category
	}
	if req.Action != nil {
		m.Action = *req.Action
	}
	if req.RedirectIP != nil {
		m.RedirectIP = *req.RedirectIP
	}
	if req.Domains != nil {
		domainsJSON, _ := json.Marshal(*req.Domains)
		m.Domains = string(domainsJSON)
	}
	if req.Regexes != nil {
		regexesJSON, _ := json.Marshal(*req.Regexes)
		m.Regexes = string(regexesJSON)
	}
	if req.ClientCIDRs != nil {
		clientCIDRsJSON, _ := json.Marshal(*req.ClientCIDRs)
		m.ClientCIDRs = string(clientCIDRsJSON)
	}
	if req.Priority != nil {
		m.Priority = *req.Priority
	}
	if req.Enabled != nil {
		m.Enabled = *req.Enabled
	}
	if req.ScheduleDays != nil {
		m.ScheduleDays = scheduleDaysJSON(*req.ScheduleDays)
	}
	if req.StartTime != nil {
		m.ScheduleStart = *req.StartTime
	}
	if req.EndTime != nil {
		m.ScheduleEnd = *req.EndTime
	}
	if req.Timezone != nil {
		m.Timezone = *req.Timezone
	}

	// Validate the merged result before persisting.
	ep := repositories.ToEnginePolicy(*m)
	if err := policy.ValidatePolicy(&ep); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}

	if err := h.Store.Policies.Update(m); err != nil {
		errMsg := "failed to update policy"
		c.JSON(http.StatusInternalServerError, ResponsePolicySingle{Status: "error", Error: &errMsg})
		return
	}

	// Persisted — apply the edit to the running engine snapshot.
	h.reloadPolicyEngine()

	c.JSON(http.StatusOK, ResponsePolicySingle{
		Status: "success",
		Data:   policyFromModel(*m),
	})
}

// DeletePolicy handles DELETE /policies/:id
func (h *APIHandler) DeletePolicy(c *gin.Context) {
	if err := h.Store.Policies.Delete(c.Param("id")); err != nil {
		status := http.StatusInternalServerError
		errMsg := "failed to delete policy"
		if err == gorm.ErrRecordNotFound {
			status = http.StatusNotFound
			errMsg = "policy not found"
		}
		c.JSON(status, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	// Persisted — apply the removal to the running engine snapshot.
	h.reloadPolicyEngine()

	c.JSON(http.StatusOK, ResponseGeneric{Status: "success", Data: map[string]interface{}{}})
}
