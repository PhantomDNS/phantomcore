// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"log"
	"os"

	"github.com/lopster568/phantomDNS/cmd/controlplane/handlers"
	"github.com/lopster568/phantomDNS/cmd/controlplane/middlewares"
	"github.com/lopster568/phantomDNS/cmd/controlplane/routes"
	"github.com/lopster568/phantomDNS/internal/config"
	client "github.com/lopster568/phantomDNS/internal/grpc/controlplane"
	"github.com/lopster568/phantomDNS/internal/inventory"
	"github.com/lopster568/phantomDNS/internal/storage/db"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database
	dbPath := "/app/data/phantomdns.db"
	if p := os.Getenv("PHANTOM_DB"); p != "" {
		dbPath = p
	}
	db.InitDB(dbPath)
	repos := repositories.NewStore(db.DB)

	// Initialize grpc client
	c, err := client.New(config.DefaultConfig.DataPlane.GRPCServer.ListenAddr)
	if err != nil {
		log.Fatalf("failed to connect to dataplane: %v", err)
	}
	defer c.Close()

	// Load the persistent configuration
	state, err := repos.SystemState.Get()
	if err != nil {
		log.Fatalf("failed to load system state: %v", err)
	}
	c.SetAcceptQueries(state.DNSEnabled)

	// Passive LAN device inventory (disabled by default; configured via
	// INVENTORY_ENABLED and DHCP_LEASES_PATH).
	deviceInventory := inventory.New(inventory.ConfigFromEnv(), nil)
	deviceInventory.Start()
	defer deviceInventory.Stop()

	// Initialize Gin router
	apiHandler := handlers.NewAPIHandler(*repos, c, deviceInventory)
	r := gin.Default()
	r.Use(middlewares.Logger())

	// CORS middleware (development-friendly). See cmd/controlplane/middlewares/cors.go
	r.Use(middlewares.CORS())

	// Auth middleware — validates Bearer token on protected routes
	r.Use(middlewares.Auth(repos.Auth))

	routes.RegisterRoutes(r, apiHandler)
	r.Run(config.DefaultConfig.ControlPlane.ListenAddr)
}
