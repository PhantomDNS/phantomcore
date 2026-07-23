package handlers

import (
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
	}
}
