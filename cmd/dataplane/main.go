package main

import (
	"github.com/lopster568/phantomDNS/internal/dnsengine"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/storage/db"
)

func main() {
	logger.Log.Info("Starting PhantomDNS Data Plane...")
	db.InitDB("/app/data/phantomdns.db")
	dnsengine.RunServer()
}
