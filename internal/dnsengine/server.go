package dnsengine

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"github.com/miekg/dns"
)

type Server struct {
	upstreamManager *UpstreamManager
	repos           *repositories.Store
	cfg             config.DataPlaneConfig
}

func NewServer(cfg config.DataPlaneConfig, repos *repositories.Store) (*Server, error) {
	mgr, err := NewUpstreamManager(cfg.UpstreamResolvers, 4)
	if err != nil {
		return nil, err
	}
	return &Server{
		upstreamManager: mgr,
		repos:           repos,
		cfg:             cfg,
	}, nil
}

func (s *Server) Run() {
	defer s.upstreamManager.Close()

	// bind handler for DNS request
	dns.HandleFunc(".", handleDnsRequest)

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
