// Just a glue which binds everything together and runs the DNS server on the Network
// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/miekg/dns"
)

type Server struct {
	cfg    config.DataPlaneConfig
	engine *Engine
}

func NewServer(cfg config.DataPlaneConfig, engine *Engine) (*Server, error) {
	return &Server{
		cfg:    cfg,
		engine: engine,
	}, nil
}

func (s *Server) Run() {
	defer s.engine.upstreamManager.Close()

	// bind handler for DNS request
	dns.HandleFunc(".", s.engine.ProcessDNSQuery)

	tcpSrv := &dns.Server{Addr: s.cfg.ListenAddr, Net: "tcp"}
	udpSrv := &dns.Server{Addr: s.cfg.ListenAddr, Net: "udp"}

	// Start servers
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
