// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/blocklist"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// categoryFetchBudget bounds how long enabling a category may spend fetching and
// aggregating its feeds before the request gives up.
const categoryFetchBudget = 90 * time.Second

// Category is the API representation of a curated filtering category.
type Category struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Type         string `json:"type"` // "security" | "content"
	Enabled      bool   `json:"enabled"`
	FeedsCount   int    `json:"feeds_count"`
	DomainsCount int64  `json:"domains_count"`
}

type CategoryListData struct {
	TotalCategories   int        `json:"total_categories"`
	EnabledCategories int        `json:"enabled_categories"`
	List              []Category `json:"list"`
}

type ResponseCategoryList struct {
	Status string           `json:"status"`
	Data   CategoryListData `json:"data"`
	Error  *string          `json:"error"`
}

type ResponseCategorySingle struct {
	Status string   `json:"status"`
	Data   Category `json:"data"`
	Error  *string  `json:"error"`
}

// ToggleCategoryRequest enables or disables a category.
type ToggleCategoryRequest struct {
	Enabled bool `json:"enabled"`
}

// enabledState returns the persisted Enabled flag for a category name, defaulting to
// false when no row has been created yet (categories are off until enabled).
func (h *APIHandler) categoryEnabled(name string) bool {
	if cat, err := h.Store.Categories.GetByName(name); err == nil {
		return cat.Enabled
	}
	return false
}

// ListCategories handles GET /categories. It reports the full catalog (the source of
// truth for which categories exist and their feeds) merged with the persisted
// enable/disable state and the live domain count of each enabled category.
func (h *APIHandler) ListCategories(c *gin.Context) {
	defs := h.catalog().Categories
	counts, err := h.Store.Blocklist.CountEntriesGroupedBySource()
	if err != nil {
		counts = map[string]int64{}
	}

	list := make([]Category, 0, len(defs))
	enabledCount := 0
	for _, def := range defs {
		enabled := h.categoryEnabled(def.Name)
		if enabled {
			enabledCount++
		}
		list = append(list, Category{
			Name:         def.Name,
			Description:  def.Description,
			Type:         def.Type,
			Enabled:      enabled,
			FeedsCount:   len(def.Feeds),
			DomainsCount: counts[blocklist.CategorySourceID(def.Name)],
		})
	}

	c.JSON(http.StatusOK, ResponseCategoryList{
		Status: "success",
		Data: CategoryListData{
			TotalCategories:   len(list),
			EnabledCategories: enabledCount,
			List:              list,
		},
	})
}

// GetCategory handles GET /categories/:name.
func (h *APIHandler) GetCategory(c *gin.Context) {
	def, ok := h.catalog().Category(c.Param("name"))
	if !ok {
		errMsg := "unknown category"
		c.JSON(http.StatusNotFound, ResponseCategorySingle{Status: "error", Error: &errMsg})
		return
	}
	count, _ := h.Store.Blocklist.CountEntriesBySource(blocklist.CategorySourceID(def.Name))
	c.JSON(http.StatusOK, ResponseCategorySingle{
		Status: "success",
		Data: Category{
			Name:         def.Name,
			Description:  def.Description,
			Type:         def.Type,
			Enabled:      h.categoryEnabled(def.Name),
			FeedsCount:   len(def.Feeds),
			DomainsCount: count,
		},
	})
}

// ToggleCategory handles PATCH /categories/:name. Enabling aggregates the category's
// curated feeds through the real blocklist engine (dedup across feeds) and stores the
// result under a namespaced aggregate source; disabling drops those entries so the
// dataplane stops blocking them. The toggle state is persisted either way.
func (h *APIHandler) ToggleCategory(c *gin.Context) {
	name := c.Param("name")
	def, ok := h.catalog().Category(name)
	if !ok {
		errMsg := "unknown category"
		c.JSON(http.StatusNotFound, ResponseCategorySingle{Status: "error", Error: &errMsg})
		return
	}

	var req ToggleCategoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseCategorySingle{Status: "error", Error: &errMsg})
		return
	}

	// Seed the row from the catalog so SetEnabled has something to update.
	row := &models.Category{Name: def.Name, Description: def.Description, Type: def.Type}
	if err := h.Store.Categories.EnsureExists(row); err != nil {
		errMsg := "failed to persist category"
		c.JSON(http.StatusInternalServerError, ResponseCategorySingle{Status: "error", Error: &errMsg})
		return
	}

	sourceID := blocklist.CategorySourceID(def.Name)
	// Always clear existing aggregated entries first: on enable we rebuild them, on
	// disable they must go away.
	if err := h.Store.Blocklist.DeleteEntriesBySource(sourceID); err != nil {
		log.Printf("failed to clear entries for category %s: %v", name, err)
	}

	var count int64
	if req.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), categoryFetchBudget)
		defer cancel()
		engine := blocklist.NewEngine(h.Store.Blocklist)
		n, err := engine.AggregateFeeds(ctx, sourceID, "Category: "+def.Name, def.Name, def.Feeds)
		if err != nil {
			errMsg := "failed to aggregate category feeds: " + err.Error()
			c.JSON(http.StatusBadGateway, ResponseCategorySingle{Status: "error", Error: &errMsg})
			return
		}
		count = int64(n)
	}

	if err := h.Store.Categories.SetEnabled(def.Name, req.Enabled); err != nil {
		errMsg := "failed to update category state"
		c.JSON(http.StatusInternalServerError, ResponseCategorySingle{Status: "error", Error: &errMsg})
		return
	}

	c.JSON(http.StatusOK, ResponseCategorySingle{
		Status: "success",
		Data: Category{
			Name:         def.Name,
			Description:  def.Description,
			Type:         def.Type,
			Enabled:      req.Enabled,
			FeedsCount:   len(def.Feeds),
			DomainsCount: count,
		},
	})
}
