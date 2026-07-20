package handlers

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/blocklist"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

const (
	// blocklistFetchWait bounds how long a create/update request blocks while the
	// initial fetch/parse/store runs. If the fetch takes longer (large or slow list),
	// the request returns and entries keep populating in the background.
	blocklistFetchWait = 30 * time.Second
	// blocklistFetchBudget caps the total time a background fetch may run so a slow or
	// unreachable source can never leak a goroutine indefinitely.
	blocklistFetchBudget = 2 * time.Minute
)

// Blocklist represents a blocklist source in API responses
type Blocklist struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Format       string    `json:"format"`
	Category     string    `json:"category"`
	DomainsCount int64     `json:"domains_count"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type BlocklistListData struct {
	TotalBlocklists int         `json:"total_blocklists"`
	TotalDomains    int64       `json:"total_domains"`
	ActiveLists     []Blocklist `json:"active_lists"`
}

type ResponseBlocklistList struct {
	Status string            `json:"status"`
	Data   BlocklistListData `json:"data"`
	Error  *string           `json:"error"`
}

type ResponseBlocklistSingle struct {
	Status string    `json:"status"`
	Data   Blocklist `json:"data"`
	Error  *string   `json:"error"`
}

type CreateBlocklistRequest struct {
	ID       string `json:"id" binding:"required"`
	Name     string `json:"name" binding:"required"`
	URL      string `json:"url" binding:"required"`
	Format   string `json:"format" binding:"required"`
	Category string `json:"category"`
}

// UpdateBlocklistRequest carries partial edits. Nil fields are left unchanged, which
// enables the inline-edit flow (I-004) and a simple enable/disable toggle.
type UpdateBlocklistRequest struct {
	Name     *string `json:"name"`
	URL      *string `json:"url"`
	Format   *string `json:"format"`
	Category *string `json:"category"`
	Enabled  *bool   `json:"enabled"`
}

func blocklistFromSource(src models.BlocklistSource, count int64) Blocklist {
	return Blocklist{
		ID:           src.ID,
		Name:         src.Name,
		URL:          src.URL,
		Format:       src.Format,
		Category:     src.Category,
		DomainsCount: count,
		Enabled:      src.Enabled,
		CreatedAt:    src.CreatedAt,
		UpdatedAt:    src.UpdatedAt,
	}
}

// isHTTPURL guards against SSRF by only allowing http(s) blocklist sources, matching
// the validation used during initial setup.
func isHTTPURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

// refreshSource runs the real fetch/parse/store engine for a source in the background.
// It returns a channel that receives the fetch error when it completes. The fetch runs
// against context.Background() (not the request context) so it keeps populating entries
// even after the HTTP handler has returned.
func (h *APIHandler) refreshSource(src models.BlocklistSource) <-chan error {
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), blocklistFetchBudget)
		defer cancel()
		engine := blocklist.NewEngine(h.Store.Blocklist)
		done <- engine.UpdateSource(ctx, src, src.ETag)
	}()
	return done
}

// waitForCount blocks up to blocklistFetchWait for a refresh to finish, then returns the
// current persisted entry count for the source. If the fetch is still running it returns
// the count so far while the fetch continues in the background.
func (h *APIHandler) waitForCount(id string, done <-chan error) int64 {
	select {
	case err := <-done:
		if err != nil {
			log.Printf("blocklist refresh failed for %s: %v", id, err)
		}
	case <-time.After(blocklistFetchWait):
		log.Printf("blocklist refresh for %s still running; domains will populate in background", id)
	}
	count, err := h.Store.Blocklist.CountEntriesBySource(id)
	if err != nil {
		return 0
	}
	return count
}

// ListBlocklists handles GET /blocklists
func (h *APIHandler) ListBlocklists(c *gin.Context) {
	sources, err := h.Store.Blocklist.ListSources()
	if err != nil {
		errMsg := "failed to fetch blocklist sources"
		c.JSON(http.StatusInternalServerError, ResponseBlocklistList{Status: "error", Error: &errMsg})
		return
	}

	counts, err := h.Store.Blocklist.CountEntriesGroupedBySource()
	if err != nil {
		counts = map[string]int64{}
	}

	var lists []Blocklist
	var totalDomains int64
	for _, src := range sources {
		count := counts[src.ID]
		totalDomains += count
		lists = append(lists, blocklistFromSource(src, count))
	}

	c.JSON(http.StatusOK, ResponseBlocklistList{
		Status: "success",
		Data: BlocklistListData{
			TotalBlocklists: len(lists),
			TotalDomains:    totalDomains,
			ActiveLists:     lists,
		},
	})
}

// GetBlocklist handles GET /blocklists/:id
func (h *APIHandler) GetBlocklist(c *gin.Context) {
	src, err := h.Store.Blocklist.GetSource(c.Param("id"))
	if err != nil {
		errMsg := "blocklist not found"
		c.JSON(http.StatusNotFound, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}
	count, _ := h.Store.Blocklist.CountEntriesBySource(src.ID)
	c.JSON(http.StatusOK, ResponseBlocklistSingle{
		Status: "success",
		Data:   blocklistFromSource(*src, count),
	})
}

// CreateBlocklist handles POST /blocklists
func (h *APIHandler) CreateBlocklist(c *gin.Context) {
	var req CreateBlocklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}

	if !isHTTPURL(req.URL) {
		errMsg := "url must use http:// or https://"
		c.JSON(http.StatusBadRequest, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}

	// Reject duplicate IDs with a clear 409 rather than a 500 from the DB layer.
	if _, err := h.Store.Blocklist.GetSource(req.ID); err == nil {
		errMsg := "blocklist with this id already exists"
		c.JSON(http.StatusConflict, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}

	src := &models.BlocklistSource{
		ID:        req.ID,
		Name:      req.Name,
		URL:       req.URL,
		Format:    req.Format,
		Category:  req.Category,
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	if err := h.Store.Blocklist.CreateSource(src); err != nil {
		errMsg := "failed to create blocklist source"
		c.JSON(http.StatusInternalServerError, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}

	// Trigger the real fetch/parse/store so domains_count is actually populated
	// instead of the previous hard-coded 0 (P0.1, I-004).
	count := h.waitForCount(src.ID, h.refreshSource(*src))

	// Reload to pick up ETag/UpdatedAt written by the engine.
	if updated, err := h.Store.Blocklist.GetSource(src.ID); err == nil {
		src = updated
	}

	c.JSON(http.StatusCreated, ResponseBlocklistSingle{
		Status: "success",
		Data:   blocklistFromSource(*src, count),
	})
}

// UpdateBlocklist handles PUT/PATCH /blocklists/:id — inline edit and enable/disable toggle.
func (h *APIHandler) UpdateBlocklist(c *gin.Context) {
	id := c.Param("id")
	src, err := h.Store.Blocklist.GetSource(id)
	if err != nil {
		errMsg := "blocklist not found"
		c.JSON(http.StatusNotFound, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}

	var req UpdateBlocklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}

	wasEnabled := src.Enabled
	sourceChanged := false // URL or format changed → entries must be re-fetched

	if req.Name != nil {
		src.Name = *req.Name
	}
	if req.URL != nil {
		if !isHTTPURL(*req.URL) {
			errMsg := "url must use http:// or https://"
			c.JSON(http.StatusBadRequest, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
			return
		}
		if *req.URL != src.URL {
			sourceChanged = true
		}
		src.URL = *req.URL
	}
	if req.Format != nil {
		if *req.Format != src.Format {
			sourceChanged = true
		}
		src.Format = *req.Format
	}
	if req.Category != nil {
		src.Category = *req.Category
	}
	if req.Enabled != nil {
		src.Enabled = *req.Enabled
	}

	// A refresh is needed when the source is (re)enabled or its URL/format changed.
	needsRefresh := src.Enabled && (!wasEnabled || sourceChanged)
	if needsRefresh {
		// Drop the stored ETag so the conditional fetch does not short-circuit with 304.
		src.ETag = ""
	}

	if err := h.Store.Blocklist.UpdateSource(src); err != nil {
		errMsg := "failed to update blocklist source"
		c.JSON(http.StatusInternalServerError, ResponseBlocklistSingle{Status: "error", Error: &errMsg})
		return
	}

	// Reconcile the dataplane checker (which reads entries live from the DB) with the
	// new desired state.
	var count int64
	switch {
	case !src.Enabled:
		// Disabled: drop its entries so the dataplane stops blocking them.
		if wasEnabled {
			if err := h.Store.Blocklist.DeleteEntriesBySource(id); err != nil {
				log.Printf("failed to clear entries for disabled blocklist %s: %v", id, err)
			}
		}
		count = 0
	case needsRefresh:
		// Clear any stale entries, then (re)fetch/parse/store.
		if err := h.Store.Blocklist.DeleteEntriesBySource(id); err != nil {
			log.Printf("failed to clear stale entries for blocklist %s: %v", id, err)
		}
		count = h.waitForCount(id, h.refreshSource(*src))
	default:
		count, _ = h.Store.Blocklist.CountEntriesBySource(id)
	}

	if updated, err := h.Store.Blocklist.GetSource(id); err == nil {
		src = updated
	}

	c.JSON(http.StatusOK, ResponseBlocklistSingle{
		Status: "success",
		Data:   blocklistFromSource(*src, count),
	})
}

// DeleteBlocklist handles DELETE /blocklists/:id
func (h *APIHandler) DeleteBlocklist(c *gin.Context) {
	// DeleteSource cascades to the source's entries + snapshots, so the dataplane's live
	// blocklist view stops matching those domains immediately.
	if err := h.Store.Blocklist.DeleteSource(c.Param("id")); err != nil {
		errMsg := "blocklist not found"
		c.JSON(http.StatusNotFound, ResponseGeneric{Status: "error", Error: &errMsg})
		return
	}
	c.JSON(http.StatusOK, ResponseGeneric{Status: "success", Data: map[string]interface{}{}})
}
