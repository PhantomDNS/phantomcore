package main

import (
	"github.com/lopster568/phantomDNS/internal/dnsengine"
	"github.com/lopster568/phantomDNS/internal/logger"
)

func main() {
	logger.Log.Info("Starting PhantomDNS Data Plane...")
	dnsengine.RunServer()
}
