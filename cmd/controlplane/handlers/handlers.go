package handlers

import (
	client "github.com/lopster568/phantomDNS/internal/grpc/controlplane"
	"github.com/lopster568/phantomDNS/internal/inventory"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

// APIHandler contains dependencies for API endpoints
type APIHandler struct {
	Store           repositories.Store
	DataPlaneClient *client.Client
	// Inventory is the passive LAN device inventory. It may be nil when the
	// feature is disabled; handlers must treat that as an empty inventory.
	Inventory *inventory.Inventory
}

func NewAPIHandler(
	store repositories.Store,
	dataPlaneClient *client.Client,
	deviceInventory *inventory.Inventory,
) *APIHandler {
	return &APIHandler{
		Store:           store,
		DataPlaneClient: dataPlaneClient,
		Inventory:       deviceInventory,
	}
}
