package handlers

import (
	"github.com/lopster568/phantomDNS/internal/blocklist"
	client "github.com/lopster568/phantomDNS/internal/grpc/controlplane"
	"github.com/lopster568/phantomDNS/internal/inventory"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

// APIHandler contains dependencies for API endpoints
type APIHandler struct {
	Store           repositories.Store
	DataPlaneClient *client.Client
	// Inventory is the passive LAN device inventory. It may be nil when the
	// feature is disabled; handlers must treat that as an empty inventory.
	Inventory *inventory.Inventory
	// PolicyEngine holds the in-process policy snapshot. Mutating policy
	// handlers reload it immediately after persisting so changes take effect
	// without waiting for the dataplane's periodic DB poll. Optional: when
	// nil, storage remains the source of truth and the dataplane picks up
	// changes on its next reload.
	PolicyEngine *policy.Engine
	// Catalog is the curated category/collection catalog backing the filtering
	// endpoints. It defaults to blocklist.DefaultCatalog() and is a field so tests can
	// substitute feeds pointing at local servers.
	Catalog *blocklist.Catalog
}

func NewAPIHandler(
	store repositories.Store,
	dataPlaneClient *client.Client,
	deviceInventory *inventory.Inventory,
	policyEngine *policy.Engine,
) *APIHandler {
	return &APIHandler{
		Store:           store,
		DataPlaneClient: dataPlaneClient,
		Inventory:       deviceInventory,
		PolicyEngine:    policyEngine,
		Catalog:         blocklist.DefaultCatalog(),
	}
}

// catalog returns the handler's catalog, falling back to the built-in default when the
// field was left unset (e.g. an APIHandler constructed literally in a test).
func (h *APIHandler) catalog() *blocklist.Catalog {
	if h.Catalog == nil {
		h.Catalog = blocklist.DefaultCatalog()
	}
	return h.Catalog
}
