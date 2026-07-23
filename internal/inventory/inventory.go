// SPDX-License-Identifier: GPL-3.0-or-later

// Package inventory maintains a passive map of devices seen on the local
// network. It is the identity foundation for per-client policy and
// infected-device alerting.
//
// The inventory is built from the kernel ARP table (Linux) and, optionally, a
// dnsmasq-style DHCP lease file. Entries are keyed by IP and carry the MAC,
// hostname and first/last-seen timestamps. Collection is passive (read-only)
// and disabled by default.
package inventory

import (
	"os"
	"sort"
	"sync"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
)

// DefaultRefreshInterval is used when a Config does not specify one.
const DefaultRefreshInterval = 60 * time.Second

// Device is a single host observed on the LAN, keyed by its IP address.
type Device struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Hostname  string    `json:"hostname"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Clock abstracts time so that seen timestamps are deterministic in tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Config controls the inventory collector.
type Config struct {
	// Enabled turns collection on. Default false (off).
	Enabled bool
	// DHCPLeasesPath, when set, is a dnsmasq-style lease file that is parsed
	// on each refresh to enrich devices with hostnames. Empty disables DHCP
	// enrichment.
	DHCPLeasesPath string
	// RefreshInterval is how often the ARP/DHCP sources are re-read. A value
	// <= 0 falls back to DefaultRefreshInterval.
	RefreshInterval time.Duration
}

// ConfigFromEnv builds a Config from environment variables:
//
//	INVENTORY_ENABLED   ("1"/"true"/"yes"/"on") enables collection (default off)
//	DHCP_LEASES_PATH    path to a dnsmasq-style lease file (optional)
func ConfigFromEnv() Config {
	cfg := Config{RefreshInterval: DefaultRefreshInterval}
	if v := os.Getenv("INVENTORY_ENABLED"); v != "" {
		cfg.Enabled = parseBool(v)
	}
	if p := os.Getenv("DHCP_LEASES_PATH"); p != "" {
		cfg.DHCPLeasesPath = p
	}
	return cfg
}

func parseBool(v string) bool {
	switch v {
	case "1", "t", "T", "true", "TRUE", "True", "yes", "YES", "on", "ON":
		return true
	default:
		return false
	}
}

// Inventory is a thread-safe device map with periodic refresh.
type Inventory struct {
	cfg   Config
	clock Clock

	mu      sync.RWMutex
	devices map[string]Device // IP -> Device

	stopCh chan struct{}
	stop   sync.Once
	wg     sync.WaitGroup
}

// New constructs an Inventory. A nil clock defaults to wall-clock time.
func New(cfg Config, clock Clock) *Inventory {
	if clock == nil {
		clock = realClock{}
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	}
	return &Inventory{
		cfg:     cfg,
		clock:   clock,
		devices: make(map[string]Device),
		stopCh:  make(chan struct{}),
	}
}

// Enabled reports whether collection is on.
func (inv *Inventory) Enabled() bool { return inv.cfg.Enabled }

// Start performs an initial refresh and then refreshes on a ticker until
// Stop is called. It is a no-op when the inventory is disabled.
func (inv *Inventory) Start() {
	if !inv.cfg.Enabled {
		return
	}
	inv.refresh()
	inv.wg.Add(1)
	go func() {
		defer inv.wg.Done()
		ticker := time.NewTicker(inv.cfg.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-inv.stopCh:
				return
			case <-ticker.C:
				inv.refresh()
			}
		}
	}()
}

// Stop halts the background refresh loop and waits for it to exit. Safe to
// call multiple times and safe when Start was never called.
func (inv *Inventory) Stop() {
	inv.stop.Do(func() { close(inv.stopCh) })
	inv.wg.Wait()
}

// Devices returns a snapshot of the inventory sorted by IP. The returned
// slice is a copy and safe for the caller to mutate.
func (inv *Inventory) Devices() []Device {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := make([]Device, 0, len(inv.devices))
	for _, d := range inv.devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// refresh re-reads the enabled sources and merges them into the device map.
// It is a no-op when disabled so that no system files are touched.
func (inv *Inventory) refresh() {
	if !inv.cfg.Enabled {
		return
	}
	arps := readARPTable()

	var leases []dhcpLease
	if inv.cfg.DHCPLeasesPath != "" {
		if data, err := os.ReadFile(inv.cfg.DHCPLeasesPath); err == nil {
			leases = parseDHCPLeases(data)
		} else {
			logger.Log.Warnf("inventory: failed to read DHCP leases (%s): %v", inv.cfg.DHCPLeasesPath, err)
		}
	}

	inv.merge(arps, leases)
}

// observation is the merged view of what a single IP looked like this cycle.
type observation struct {
	MAC      string
	Hostname string
}

// merge folds a set of ARP entries and DHCP leases into the device map,
// preserving FirstSeen for known IPs and stamping LastSeen for every IP seen
// this cycle. ARP supplies MAC addresses; DHCP supplies hostnames (and MAC as
// a fallback).
func (inv *Inventory) merge(arps []arpEntry, leases []dhcpLease) {
	obs := make(map[string]observation)
	for _, a := range arps {
		o := obs[a.IP]
		if a.MAC != "" {
			o.MAC = a.MAC
		}
		obs[a.IP] = o
	}
	for _, l := range leases {
		o := obs[l.IP]
		if l.MAC != "" {
			o.MAC = l.MAC
		}
		if l.Hostname != "" {
			o.Hostname = l.Hostname
		}
		obs[l.IP] = o
	}

	now := inv.clock.Now()
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for ip, o := range obs {
		d, ok := inv.devices[ip]
		if !ok {
			inv.devices[ip] = Device{
				IP:        ip,
				MAC:       o.MAC,
				Hostname:  o.Hostname,
				FirstSeen: now,
				LastSeen:  now,
			}
			continue
		}
		if o.MAC != "" {
			d.MAC = o.MAC
		}
		if o.Hostname != "" {
			d.Hostname = o.Hostname
		}
		d.LastSeen = now
		inv.devices[ip] = d
	}
}
