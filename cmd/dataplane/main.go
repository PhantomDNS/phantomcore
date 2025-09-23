package main

// SPDX-License-Identifier: GPL-3.0-or-later
import (
	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/dnsengine"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/storage/db"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

func main() {
	logger.Log.Info("Starting PhantomDNS Data Plane...")
	// 1. Initialize DB
	db.InitDB("/app/data/phantomdns.db")
	// 2. Initialize Repositories (store)
	repos := repositories.NewStore(db.DB)
	// 3. Initialize DNS Engine with default config and repos
	engine, err := dnsengine.NewDNSEngine(config.DefaultConfig.DataPlane, repos)
	if err != nil {
		logger.Log.Fatal("Failed to create DNS engine: " + err.Error())
	}
	// 4. Initialize and Run Server with the engine
	srv, err := dnsengine.NewServer(config.DefaultConfig.DataPlane, engine)
	if err != nil {
		logger.Log.Fatal("Failed to create server: " + err.Error())
	}
	srv.Run()
}
