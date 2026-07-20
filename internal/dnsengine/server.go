// Just a glue which binds everything together and runs the DNS server on the Network
// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"net"
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
	defer s.engine.Shutdown()

	// bind handler for DNS request
	dns.HandleFunc(".", s.engine.ProcessDNSQuery)

	tcpSrv := &dns.Server{Addr: s.cfg.ListenAddr, Net: "tcp"}
	udpSrv := &dns.Server{Addr: s.cfg.ListenAddr, Net: "udp"}

	tcpErr := make(chan error, 1)
	udpErr := make(chan error, 1)

	started := make(chan struct{}, 2)

	// Start servers
	go func() {
		logger.Log.Info("Starting TCP server on ", tcpSrv.Addr)
		ln, err := net.Listen("tcp", s.cfg.ListenAddr)
		if err != nil {
			tcpErr <- err
			return
		}

		started <- struct{}{}

		tcpSrv.Listener = ln
		if err := tcpSrv.ActivateAndServe(); err != nil {
			tcpErr <- err
		}

	}()
	go func() {
		logger.Log.Info("Starting UDP server on ", udpSrv.Addr)
		pc, err := net.ListenPacket("udp", s.cfg.ListenAddr)
		if err != nil {
			udpErr <- err
			return
		}

		started <- struct{}{}

		udpSrv.PacketConn = pc
		if err := udpSrv.ActivateAndServe(); err != nil {
			udpErr <- err
		}

	}()

	for i := 0; i < 2; i++ {
		select {
		case err := <-tcpErr:
			logger.Log.Error("TCP failed during startup: ", err)
			return
		case err := <-udpErr:
			logger.Log.Error("UDP failed during startup: ", err)
			return
		case <-started:
			// one server started
		}
	}

	s.engine.state.acceptQueries.Store(true) // both are up
	logger.Log.Info("DNS servers are up and running")
	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	logger.Log.Info("entering drain mode")
	s.engine.state.acceptQueries.Store(false)
	udpSrv.Shutdown()
	tcpSrv.Shutdown()

	logger.Log.Info("exited")
}
