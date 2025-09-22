package main

import (
	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/dnsengine"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/storage/db"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

func main() {
	logger.Log.Info("Starting PhantomDNS Data Plane...")
	db.InitDB("/app/data/phantomdns.db")
	repos := &repositories.Store{}
	srv, err := dnsengine.NewEngine(config.DefaultConfig.DataPlane, repos)
	if err != nil {
		logger.Log.Fatal("Failed to create server: " + err.Error())
	}
	srv.Run()
}
