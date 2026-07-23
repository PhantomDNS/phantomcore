package handlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ConfigVersion is the schema version stamped on every export and required on
// import. Bump this only for backward-incompatible changes to the shape.
const ConfigVersion = "1"

// validPolicyActions mirrors the actions the policy engine understands.
var validPolicyActions = map[string]bool{
	"BLOCK":    true,
	"ALLOW":    true,
	"REDIRECT": true,
}

// ConfigPolicy is a policy as it appears in an exported config. It intentionally
// omits server-managed timestamps so exports are stable and diffable.
type ConfigPolicy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Action      string   `json:"action"`
	RedirectIP  string   `json:"redirect_ip,omitempty"`
	Domains     []string `json:"domains"`
	Priority    int      `json:"priority"`
	Enabled     bool     `json:"enabled"`
}

// ConfigBlocklist is a blocklist source as it appears in an exported config.
// Downloaded entries and timestamps are runtime state, not config, so they are
// excluded — only the source definition round-trips.
type ConfigBlocklist struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Format   string `json:"format"`
	Category string `json:"category"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
}

// ConfigSettings holds the key persisted system settings.
type ConfigSettings struct {
	DNSEnabled    bool `json:"dns_enabled"`
	PolicyEnabled bool `json:"policy_enabled"`
}

// Config is the full versioned, portable representation of a HydraDNS
// configuration: policies, blocklist sources and key settings.
type Config struct {
	Version    string            `json:"version"`
	Policies   []ConfigPolicy    `json:"policies"`
	Blocklists []ConfigBlocklist `json:"blocklists"`
	Settings   ConfigSettings    `json:"settings"`
}

// ImportSummary is returned from POST /config/import describing what an import
// did (or, for a dry run, what it would do).
type ImportSummary struct {
	DryRun             bool     `json:"dry_run"`
	PoliciesImported   int      `json:"policies_imported"`
	BlocklistsImported int      `json:"blocklists_imported"`
	SettingsApplied    bool     `json:"settings_applied"`
	Warnings           []string `json:"warnings,omitempty"`
}

// ExportConfig handles GET /api/v1/config/export.
// It dumps the current policies, blocklist sources and key settings as a single
// versioned JSON document for backup, cloning or diffing.
func (h *APIHandler) ExportConfig(c *gin.Context) {
	cfg, err := h.buildExport()
	if err != nil {
		errMsg := "failed to export config"
		c.JSON(http.StatusInternalServerError, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}
	c.JSON(http.StatusOK, ResponseGeneric{Status: "success", Data: cfg})
}

// buildExport reads the live config out of the repositories and normalises it
// into a deterministic (id-sorted, timestamp-free) document so that
// export → import → export round-trips byte-for-byte.
func (h *APIHandler) buildExport() (*Config, error) {
	policyModels, err := h.Store.Policies.List()
	if err != nil {
		return nil, err
	}
	policies := make([]ConfigPolicy, 0, len(policyModels))
	for _, m := range policyModels {
		var domains []string
		if m.Domains != "" {
			_ = json.Unmarshal([]byte(m.Domains), &domains)
		}
		policies = append(policies, ConfigPolicy{
			ID:          m.ID,
			Name:        m.Name,
			Description: m.Description,
			Category:    m.Category,
			Action:      m.Action,
			RedirectIP:  m.RedirectIP,
			Domains:     domains,
			Priority:    m.Priority,
			Enabled:     m.Enabled,
		})
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })

	sources, err := h.Store.Blocklist.ListSources()
	if err != nil {
		return nil, err
	}
	blocklists := make([]ConfigBlocklist, 0, len(sources))
	for _, src := range sources {
		blocklists = append(blocklists, ConfigBlocklist{
			ID:       src.ID,
			Name:     src.Name,
			URL:      src.URL,
			Format:   src.Format,
			Category: src.Category,
			Priority: src.Priority,
			Enabled:  src.Enabled,
		})
	}
	sort.Slice(blocklists, func(i, j int) bool { return blocklists[i].ID < blocklists[j].ID })

	state, err := h.Store.SystemState.Get()
	if err != nil {
		return nil, err
	}

	return &Config{
		Version:    ConfigVersion,
		Policies:   policies,
		Blocklists: blocklists,
		Settings: ConfigSettings{
			DNSEnabled:    state.DNSEnabled,
			PolicyEnabled: state.PolicyEnabled,
		},
	}, nil
}

// ImportConfig handles POST /api/v1/config/import.
// It validates the supplied config and, unless ?dry_run=true, applies it
// atomically (all-or-nothing) via the real repositories and reloads the engine.
func (h *APIHandler) ImportConfig(c *gin.Context) {
	var cfg Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		errMsg := "invalid config payload: " + err.Error()
		c.JSON(http.StatusBadRequest, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	if err := validateConfig(&cfg); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	dryRun := strings.EqualFold(c.Query("dry_run"), "true")

	summary := ImportSummary{
		DryRun:             dryRun,
		PoliciesImported:   len(cfg.Policies),
		BlocklistsImported: len(cfg.Blocklists),
		SettingsApplied:    true,
	}

	if dryRun {
		// Validation succeeded; persist nothing.
		c.JSON(http.StatusOK, ResponseGeneric{Status: "success", Data: summary})
		return
	}

	if err := h.applyConfig(&cfg); err != nil {
		errMsg := "failed to apply config"
		c.JSON(http.StatusInternalServerError, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}

	// Reload the engine so the dataplane reflects the imported settings.
	// Best-effort: persistence is the source of truth, so a dataplane hiccup
	// does not fail the import — it is surfaced as a warning instead.
	if h.DataPlaneClient != nil {
		if err := h.DataPlaneClient.SetAcceptQueries(cfg.Settings.DNSEnabled); err != nil {
			summary.Warnings = append(summary.Warnings, "config persisted but engine reload failed: "+err.Error())
		}
	}

	c.JSON(http.StatusOK, ResponseGeneric{Status: "success", Data: summary})
}

// validateConfig checks a config is well-formed before anything is persisted.
func validateConfig(cfg *Config) error {
	if cfg.Version == "" {
		return &configError{"config version is required"}
	}
	if cfg.Version != ConfigVersion {
		return &configError{"unsupported config version: " + cfg.Version}
	}

	seenPolicies := make(map[string]bool, len(cfg.Policies))
	for _, p := range cfg.Policies {
		if p.ID == "" {
			return &configError{"policy id is required"}
		}
		if seenPolicies[p.ID] {
			return &configError{"duplicate policy id: " + p.ID}
		}
		seenPolicies[p.ID] = true
		if p.Name == "" {
			return &configError{"policy name is required for id: " + p.ID}
		}
		if !validPolicyActions[p.Action] {
			return &configError{"invalid action for policy " + p.ID + ": " + p.Action}
		}
	}

	seenBlocklists := make(map[string]bool, len(cfg.Blocklists))
	for _, b := range cfg.Blocklists {
		if b.ID == "" {
			return &configError{"blocklist id is required"}
		}
		if seenBlocklists[b.ID] {
			return &configError{"duplicate blocklist id: " + b.ID}
		}
		seenBlocklists[b.ID] = true
		if b.Name == "" {
			return &configError{"blocklist name is required for id: " + b.ID}
		}
		if b.URL == "" {
			return &configError{"blocklist url is required for id: " + b.ID}
		}
		// Guard against SSRF via non-http(s) schemes, consistent with setup.
		if !strings.HasPrefix(b.URL, "http://") && !strings.HasPrefix(b.URL, "https://") {
			return &configError{"blocklist url must use http:// or https:// for id: " + b.ID}
		}
		if b.Format == "" {
			return &configError{"blocklist format is required for id: " + b.ID}
		}
	}

	return nil
}

// applyConfig persists an already-validated config atomically. Policies and
// blocklist sources are upserted by id (merge semantics: nothing is deleted),
// and settings are updated in place. Server-managed CreatedAt timestamps of
// existing rows are preserved so re-imports stay idempotent.
func (h *APIHandler) applyConfig(cfg *Config) error {
	now := time.Now()

	return h.Store.DB.Transaction(func(tx *gorm.DB) error {
		for _, p := range cfg.Policies {
			domainsJSON, err := json.Marshal(p.Domains)
			if err != nil {
				return err
			}
			m := models.Policy{
				ID:          p.ID,
				Name:        p.Name,
				Description: p.Description,
				Category:    p.Category,
				Action:      p.Action,
				RedirectIP:  p.RedirectIP,
				Domains:     string(domainsJSON),
				Priority:    p.Priority,
				Enabled:     p.Enabled,
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"name", "description", "category", "action",
					"redirect_ip", "domains", "priority", "enabled", "updated_at",
				}),
			}).Create(&m).Error; err != nil {
				return err
			}
		}

		for _, b := range cfg.Blocklists {
			src := models.BlocklistSource{
				ID:        b.ID,
				Name:      b.Name,
				URL:       b.URL,
				Format:    b.Format,
				Category:  b.Category,
				Priority:  b.Priority,
				Enabled:   b.Enabled,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"name", "url", "format", "category", "priority", "enabled", "updated_at",
				}),
			}).Create(&src).Error; err != nil {
				return err
			}
		}

		state := models.SystemState{
			ID:            1,
			DNSEnabled:    cfg.Settings.DNSEnabled,
			PolicyEnabled: cfg.Settings.PolicyEnabled,
			UpdatedAt:     now,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"dns_enabled", "policy_enabled", "updated_at",
			}),
		}).Create(&state).Error; err != nil {
			return err
		}

		return nil
	})
}

// configError is a small typed error so validation failures carry a message
// straight into the standard error envelope.
type configError struct {
	msg string
}

func (e *configError) Error() string { return e.msg }
