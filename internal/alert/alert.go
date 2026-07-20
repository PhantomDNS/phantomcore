// SPDX-License-Identifier: GPL-3.0-or-later

// Package alert implements infected-device alerting (I-045).
//
// It watches for clients that repeatedly resolve known-malware / C2 domains
// (blocked hits). When a single client crosses a configurable threshold of
// blocked hits within a sliding window, the device behind that client IP is
// marked suspected-compromised and an alert record is produced. Alerts are
// enriched with device identity (IP + MAC + hostname) resolved from the passive
// LAN inventory; unknown devices yield an IP-only alert.
//
// The feature is off by default: alerting is enabled only when a positive
// DEVICE_ALERT_THRESHOLD is configured. Time is injected via a Clock and the
// device lookup via a DeviceResolver so the whole path is deterministic in
// tests.
package alert

import (
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
)

// DefaultWindow is the sliding window over which blocked hits are counted when
// a Config does not specify one.
const DefaultWindow = 10 * time.Minute

// DeviceInfo is the identity of a device correlated with a client IP. MAC and
// Hostname are empty when the device is unknown to the inventory.
type DeviceInfo struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// DeviceResolver maps a client IP to its device identity. It is satisfied by
// the LAN inventory (see InventoryResolver) and by fakes in tests. A lookup
// that returns false yields an IP-only alert.
type DeviceResolver interface {
	Lookup(ip string) (DeviceInfo, bool)
}

// Clock abstracts time so windowing is deterministic in tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Alert is a single infected-device alert record.
type Alert struct {
	Device    DeviceInfo `json:"device"`
	Hits      int        `json:"hits"`      // blocked hits in the window at fire time
	Threshold int        `json:"threshold"` // threshold that was crossed
	FirstHit  time.Time  `json:"first_hit"` // oldest hit still inside the window
	FiredAt   time.Time  `json:"fired_at"`  // when the threshold was crossed
	Domain    string     `json:"domain,omitempty"`
}

// Config controls the alerter.
type Config struct {
	// Threshold is the number of blocked hits from one client within Window
	// that marks the device suspected-compromised. A value <= 0 disables
	// alerting entirely (the feature default).
	Threshold int
	// Window is the sliding window over which blocked hits are counted. A
	// value <= 0 falls back to DefaultWindow.
	Window time.Duration
}

// ConfigFromEnv builds a Config from environment variables:
//
//	DEVICE_ALERT_THRESHOLD  blocked hits within the window before a device is
//	                        flagged. Default 0 (off); any positive value
//	                        enables alerting.
//	DEVICE_ALERT_WINDOW     window duration, e.g. "10m" (default 10m).
func ConfigFromEnv() Config {
	cfg := Config{Window: DefaultWindow}
	if v := os.Getenv("DEVICE_ALERT_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Threshold = n
		}
	}
	if v := os.Getenv("DEVICE_ALERT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Window = d
		}
	}
	return cfg
}

// clientCounter tracks the recent blocked-hit timestamps for one client IP.
type clientCounter struct {
	hits []time.Time
}

// Alerter counts per-client blocked hits and fires device alerts on threshold
// crossings. It is safe for concurrent use.
type Alerter struct {
	cfg   Config
	clock Clock

	mu        sync.Mutex
	resolver  DeviceResolver
	sink      func(Alert)
	counters  map[string]*clientCounter
	suspected map[string]Alert // clientIP -> latest alert
}

// NewAlerter constructs an Alerter. A nil clock defaults to wall-clock time; a
// nil resolver produces IP-only alerts.
func NewAlerter(cfg Config, resolver DeviceResolver, clock Clock) *Alerter {
	if clock == nil {
		clock = realClock{}
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	return &Alerter{
		cfg:       cfg,
		clock:     clock,
		resolver:  resolver,
		counters:  make(map[string]*clientCounter),
		suspected: make(map[string]Alert),
	}
}

// Enabled reports whether alerting is active (a positive threshold is set).
func (a *Alerter) Enabled() bool { return a.cfg.Threshold > 0 }

// SetResolver attaches (or replaces) the device resolver used to enrich alerts.
func (a *Alerter) SetResolver(r DeviceResolver) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resolver = r
}

// SetSink attaches an optional side-channel (e.g. a webhook) invoked for each
// fired alert. It is called synchronously while no lock is held; sinks that may
// block should return quickly or dispatch their own goroutine.
func (a *Alerter) SetSink(fn func(Alert)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sink = fn
}

// RecordBlocked registers one blocked hit for clientIP resolving domain. When
// the client crosses the configured threshold within the window it returns the
// fired alert and true; otherwise it returns the zero Alert and false. It is a
// no-op (false) when alerting is disabled or clientIP is empty.
func (a *Alerter) RecordBlocked(clientIP, domain string) (Alert, bool) {
	if a == nil || a.cfg.Threshold <= 0 || clientIP == "" {
		return Alert{}, false
	}

	now := a.clock.Now()
	cutoff := now.Add(-a.cfg.Window)

	a.mu.Lock()
	c := a.counters[clientIP]
	if c == nil {
		c = &clientCounter{}
		a.counters[clientIP] = c
	}
	// Drop hits that have aged out of the sliding window, then record this one.
	kept := c.hits[:0]
	for _, t := range c.hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	c.hits = append(kept, now)

	if len(c.hits) < a.cfg.Threshold {
		a.mu.Unlock()
		return Alert{}, false
	}

	// Threshold crossed: build the alert, remember the device as suspected and
	// reset the counter so we do not re-fire on every subsequent hit.
	alert := Alert{
		Device:    a.resolveLocked(clientIP),
		Hits:      len(c.hits),
		Threshold: a.cfg.Threshold,
		FirstHit:  c.hits[0],
		FiredAt:   now,
		Domain:    domain,
	}
	c.hits = c.hits[:0]
	a.suspected[clientIP] = alert
	sink := a.sink
	a.mu.Unlock()

	logger.Log.Warnf(
		"infected-device alert: client %s crossed %d blocked hits within %s (mac=%q hostname=%q, last domain %q)",
		alert.Device.IP, alert.Threshold, a.cfg.Window, alert.Device.MAC, alert.Device.Hostname, domain,
	)
	if sink != nil {
		sink(alert)
	}
	return alert, true
}

// resolveLocked builds the DeviceInfo for a client IP. Callers must hold a.mu.
func (a *Alerter) resolveLocked(clientIP string) DeviceInfo {
	dev := DeviceInfo{IP: clientIP}
	if a.resolver != nil {
		if d, ok := a.resolver.Lookup(clientIP); ok {
			dev = d
			if dev.IP == "" {
				dev.IP = clientIP
			}
		}
	}
	return dev
}

// IsSuspected reports whether a client IP has been flagged as compromised.
func (a *Alerter) IsSuspected(clientIP string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.suspected[clientIP]
	return ok
}

// Suspected returns a snapshot of the latest alert per suspected device, sorted
// by IP. The returned slice is a copy and safe for the caller to mutate.
func (a *Alerter) Suspected() []Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Alert, 0, len(a.suspected))
	for _, al := range a.suspected {
		out = append(out, al)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device.IP < out[j].Device.IP })
	return out
}
