package dnsengine

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/lopster568/phantomDNS/internal/config"
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
	tcpSrv, udpSrv := makeServer()
	go func() {
		log.Println("Starting TCP server on", tcpSrv.Addr)
		if err := tcpSrv.ListenAndServe(); err != nil {
			log.Println("TCP server failed: " + err.Error())
		}
	}()
	go func() {
		log.Println("Starting UDP server on", udpSrv.Addr)
		if err := udpSrv.ListenAndServe(); err != nil {
			log.Println("UDP server failed: " + err.Error())
		}
	}()

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("shutting down...")
	udpSrv.Shutdown()
	tcpSrv.Shutdown()
	log.Println("exited")
}
