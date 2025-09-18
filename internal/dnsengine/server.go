package dnsengine

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

var upstreamManager *UpstreamManager

func makeServer() (*dns.Server, *dns.Server) {
	logger.Log.Infof("Resolved listen address: %q", config.DefaultConfig.DataPlane.ListenAddr)
	tcpSrv := &dns.Server{Addr: config.DefaultConfig.DataPlane.ListenAddr, Net: "tcp"}
	udpSrv := &dns.Server{Addr: config.DefaultConfig.DataPlane.ListenAddr, Net: "udp"}
	return tcpSrv, udpSrv
}

func RunServer() {
	mgr, err := NewUpstreamManager(config.DefaultConfig.DataPlane.UpstreamResolvers, 4)
	if err != nil {
		logger.Log.Fatal("Failed to create UpstreamManager: " + err.Error())
	}
	upstreamManager = mgr
	defer mgr.Close()

	// Assign our custom handler to process DNS requests
	dns.HandleFunc(".", handleDnsRequest)

	// Setting up the server here
	tcpSrv, udpSrv := makeServer()
	go func() {
		logger.Log.Info("Starting TCP server on ", tcpSrv.Addr)
		if err := tcpSrv.ListenAndServe(); err != nil {
			logger.Log.Error("TCP server failed: " + err.Error())
		}
	}()
	go func() {
		logger.Log.Info("Starting UDP server on ", udpSrv.Addr)
		if err := udpSrv.ListenAndServe(); err != nil {
			logger.Log.Error("UDP server failed: " + err.Error())
		}
	}()

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	logger.Log.Info("shutting down...")
	udpSrv.Shutdown()
	tcpSrv.Shutdown()
	logger.Log.Info("exited")
}
