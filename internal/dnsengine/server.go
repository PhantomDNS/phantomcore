package dnsengine

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

func makeServer() (*dns.Server, *dns.Server) {
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}
	tcpSrv := &dns.Server{Addr: cfg.DataPlane.ListenAddr, Net: "tcp"}
	udpSrv := &dns.Server{Addr: cfg.DataPlane.ListenAddr, Net: "udp"}
	return tcpSrv, udpSrv
}

func RunServer() {
	// Assign our custom handler to process DNS requests
	dns.HandleFunc(".", handleDnsRequest)

	// Setting up the server here
	tcpSrv, udpSrv := makeServer()
	go func() {
		logger.Log.Info("Starting TCP server on", tcpSrv.Addr)
		if err := tcpSrv.ListenAndServe(); err != nil {
			logger.Log.Error("TCP server failed: " + err.Error())
		}
	}()
	go func() {
		logger.Log.Info("Starting UDP server on", udpSrv.Addr)
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
