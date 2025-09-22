package dnsengine

import "github.com/lopster568/phantomDNS/internal/storage/repositories"

type DNSEngine struct {
	upstreamManager *UpstreamManager
	repos           *repositories.Store
}

func NewEngine(mgr *UpstreamManager, repos *repositories.Store) *DNSEngine {
	return &DNSEngine{
		upstreamManager: mgr,
		repos:           repos,
	}
}
