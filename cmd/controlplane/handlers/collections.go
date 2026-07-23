// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/blocklist"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// Collection is the API representation of an app/service domain bundle (I-052).
type Collection struct {
	Name         string `json:"name"`
	App          string `json:"app"`
	Description  string `json:"description"`
	Enabled      bool   `json:"enabled"`
	DomainsCount int64  `json:"domains_count"`
}

type CollectionListData struct {
	TotalCollections   int          `json:"total_collections"`
	EnabledCollections int          `json:"enabled_collections"`
	List               []Collection `json:"list"`
}

type ResponseCollectionList struct {
	Status string             `json:"status"`
	Data   CollectionListData `json:"data"`
	Error  *string            `json:"error"`
}

type ResponseCollectionSingle struct {
	Status string     `json:"status"`
	Data   Collection `json:"data"`
	Error  *string    `json:"error"`
}

// ToggleCollectionRequest enables or disables an app/service collection.
type ToggleCollectionRequest struct {
	Enabled bool `json:"enabled"`
}

func (h *APIHandler) collectionEnabled(name string) bool {
	if col, err := h.Store.Collections.GetByName(name); err == nil {
		return col.Enabled
	}
	return false
}

// ListCollections handles GET /collections.
func (h *APIHandler) ListCollections(c *gin.Context) {
	defs := h.catalog().Collections
	counts, err := h.Store.Blocklist.CountEntriesGroupedBySource()
	if err != nil {
		counts = map[string]int64{}
	}

	list := make([]Collection, 0, len(defs))
	enabledCount := 0
	for _, def := range defs {
		enabled := h.collectionEnabled(def.Name)
		if enabled {
			enabledCount++
		}
		list = append(list, Collection{
			Name:         def.Name,
			App:          def.App,
			Description:  def.Description,
			Enabled:      enabled,
			DomainsCount: counts[blocklist.CollectionSourceID(def.Name)],
		})
	}

	c.JSON(http.StatusOK, ResponseCollectionList{
		Status: "success",
		Data: CollectionListData{
			TotalCollections:   len(list),
			EnabledCollections: enabledCount,
			List:               list,
		},
	})
}

// ToggleCollection handles PATCH /collections/:name. Enabling stores the collection's
// curated (deduped) domain bundle under a namespaced aggregate source so the dataplane
// blocks the whole app as one toggle; disabling drops those entries. The toggle state is
// persisted either way.
func (h *APIHandler) ToggleCollection(c *gin.Context) {
	name := c.Param("name")
	def, ok := h.catalog().Collection(name)
	if !ok {
		errMsg := "unknown collection"
		c.JSON(http.StatusNotFound, ResponseCollectionSingle{Status: "error", Error: &errMsg})
		return
	}

	var req ToggleCollectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errMsg := err.Error()
		c.JSON(http.StatusBadRequest, ResponseCollectionSingle{Status: "error", Error: &errMsg})
		return
	}

	row := &models.Collection{Name: def.Name, App: def.App, Description: def.Description}
	if err := h.Store.Collections.EnsureExists(row); err != nil {
		errMsg := "failed to persist collection"
		c.JSON(http.StatusInternalServerError, ResponseCollectionSingle{Status: "error", Error: &errMsg})
		return
	}

	sourceID := blocklist.CollectionSourceID(def.Name)
	if err := h.Store.Blocklist.DeleteEntriesBySource(sourceID); err != nil {
		log.Printf("failed to clear entries for collection %s: %v", name, err)
	}

	var count int64
	if req.Enabled {
		engine := blocklist.NewEngine(h.Store.Blocklist)
		n, err := engine.StoreDomains(sourceID, "Collection: "+def.App, def.Name, def.Domains)
		if err != nil {
			errMsg := "failed to store collection bundle"
			c.JSON(http.StatusInternalServerError, ResponseCollectionSingle{Status: "error", Error: &errMsg})
			return
		}
		count = int64(n)
	}

	if err := h.Store.Collections.SetEnabled(def.Name, req.Enabled); err != nil {
		errMsg := "failed to update collection state"
		c.JSON(http.StatusInternalServerError, ResponseCollectionSingle{Status: "error", Error: &errMsg})
		return
	}

	c.JSON(http.StatusOK, ResponseCollectionSingle{
		Status: "success",
		Data: Collection{
			Name:         def.Name,
			App:          def.App,
			Description:  def.Description,
			Enabled:      req.Enabled,
			DomainsCount: count,
		},
	})
}
