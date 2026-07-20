// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
)

// Event is a single DNS query event handed to the exporter. It mirrors the
// fields persisted in the query log so external systems (SIEM, syslog
// collectors, webhooks) receive the same information as the local store.
type Event struct {
	Timestamp       time.Time `json:"timestamp"`
	Domain          string    `json:"domain"`
	ClientIP        string    `json:"client_ip"`
	Action          string    `json:"action"` // allow, block, redirect, flagged, error
	IsSuspicious    bool      `json:"is_suspicious"`
	ThreatScore     float64   `json:"threat_score"`
	DetectionMethod string    `json:"detection_method"`
	ThreatReason    string    `json:"threat_reason"`
}

// Sink is a pluggable destination for query events.
type Sink interface {
	// Send delivers a single event. Implementations should be self-contained
	// and must not retain the Event after returning.
	Send(Event) error
	// Close releases any resources held by the sink.
	Close() error
}

// exportQueueSize bounds the number of pending events. When full, new events
// are dropped rather than blocking DNS resolution.
const exportQueueSize = 1024

// Exporter fans query events out to one or more sinks through a bounded,
// drop-on-full queue drained by a single background worker. This guarantees
// the hot resolution path (logQuery) never blocks on a slow syslog/webhook
// target. A nil *Exporter is a valid no-op (export disabled).
type Exporter struct {
	queue     chan Event
	sinks     []Sink
	wg        sync.WaitGroup
	closeOnce sync.Once
	dropped   atomic.Uint64
}

// NewExporter builds an Exporter from the given targets. Both arguments are
// optional; if neither is set (both empty) export is disabled and (nil, nil)
// is returned — callers must treat a nil *Exporter as "off". A target that
// fails to initialise is logged and skipped rather than failing the engine.
func NewExporter(syslogAddr, webhookURL string) (*Exporter, error) {
	var sinks []Sink

	if strings.TrimSpace(syslogAddr) != "" {
		s, err := newSyslogSink(syslogAddr)
		if err != nil {
			logger.Log.Warnf("event export: syslog sink disabled: %v", err)
		} else {
			sinks = append(sinks, s)
			logger.Log.Infof("event export: syslog sink enabled (%s)", syslogAddr)
		}
	}

	if strings.TrimSpace(webhookURL) != "" {
		sinks = append(sinks, newWebhookSink(webhookURL))
		logger.Log.Infof("event export: webhook sink enabled (%s)", webhookURL)
	}

	if len(sinks) == 0 {
		return nil, nil
	}

	e := &Exporter{
		queue: make(chan Event, exportQueueSize),
		sinks: sinks,
	}
	e.wg.Add(1)
	go e.run()
	return e, nil
}

// Export enqueues an event for delivery. It never blocks: if the queue is full
// the event is dropped and the drop counter is incremented. Safe to call on a
// nil receiver (export disabled).
func (e *Exporter) Export(ev Event) {
	if e == nil {
		return
	}
	select {
	case e.queue <- ev:
	default:
		n := e.dropped.Add(1)
		// Log sparingly to avoid amplifying pressure under sustained overflow.
		if n == 1 || n%1024 == 0 {
			logger.Log.Warnf("event export: queue full, dropped %d events", n)
		}
	}
}

// Dropped returns the total number of events dropped due to a full queue.
func (e *Exporter) Dropped() uint64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

// Close stops the worker, drains in-flight events, and closes all sinks.
// Safe to call multiple times and on a nil receiver.
func (e *Exporter) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		close(e.queue)
		e.wg.Wait()
		for _, s := range e.sinks {
			if err := s.Close(); err != nil {
				logger.Log.Warnf("event export: sink close error: %v", err)
			}
		}
	})
}

func (e *Exporter) run() {
	defer e.wg.Done()
	for ev := range e.queue {
		for _, s := range e.sinks {
			if err := s.Send(ev); err != nil {
				logger.Log.Warnf("event export: sink send failed: %v", err)
			}
		}
	}
}

// --- syslog sink (RFC 5424) ---

// Facility local0 (16) is the conventional choice for application logs.
const syslogFacilityLocal0 = 16

// syslogSDID is the RFC 5424 structured-data element ID. 32473 is the
// enterprise number reserved by RFC 5612 for documentation/examples.
const syslogSDID = "hydradns@32473"

type syslogSink struct {
	mu       sync.Mutex
	conn     net.Conn
	network  string
	address  string
	hostname string
	appName  string
	procID   string
}

// newSyslogSink parses a target of the form "udp://host:514" or
// "tcp://host:514" (scheme optional, defaults to udp) and dials it.
func newSyslogSink(addr string) (*syslogSink, error) {
	network, address, err := parseSyslogAddr(addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", network, address, err)
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "-"
	}
	return &syslogSink{
		conn:     conn,
		network:  network,
		address:  address,
		hostname: host,
		appName:  "hydradns",
		procID:   strconv.Itoa(os.Getpid()),
	}, nil
}

// parseSyslogAddr splits a syslog target into (network, address). Accepted
// forms: "udp://host:port", "tcp://host:port", or a bare "host:port"
// (defaults to udp).
func parseSyslogAddr(addr string) (network, address string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", fmt.Errorf("empty syslog address")
	}
	if strings.Contains(addr, "://") {
		u, perr := url.Parse(addr)
		if perr != nil {
			return "", "", fmt.Errorf("parse syslog addr %q: %w", addr, perr)
		}
		network = strings.ToLower(u.Scheme)
		address = u.Host
	} else {
		network = "udp"
		address = addr
	}
	switch network {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
	default:
		return "", "", fmt.Errorf("unsupported syslog network %q (use udp:// or tcp://)", network)
	}
	if address == "" {
		return "", "", fmt.Errorf("missing host:port in syslog address %q", addr)
	}
	return network, address, nil
}

func (s *syslogSink) Send(ev Event) error {
	line := formatRFC5424(s.hostname, s.appName, s.procID, ev.Timestamp, ev)
	// Non-transparent framing (RFC 6587): terminate stream messages with LF.
	if strings.HasPrefix(s.network, "tcp") {
		line += "\n"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.Write([]byte(line))
	return err
}

func (s *syslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// severityFor maps an engine action to an RFC 5424 severity level.
func severityFor(action string) int {
	switch action {
	case "error":
		return 3 // Error
	case "flagged":
		return 4 // Warning
	case "block", "redirect":
		return 5 // Notice
	default: // allow and anything else
		return 6 // Informational
	}
}

// formatRFC5424 renders an event as a single RFC 5424 syslog line. It is a
// pure function of its inputs, which keeps formatting deterministically
// testable. Any empty header field is emitted as the RFC nil value "-".
func formatRFC5424(hostname, appName, procID string, t time.Time, ev Event) string {
	pri := syslogFacilityLocal0*8 + severityFor(ev.Action)

	ts := t.UTC().Format(time.RFC3339)
	if t.IsZero() {
		ts = "-"
	}
	hostname = nilIfEmpty(hostname)
	appName = nilIfEmpty(appName)
	procID = nilIfEmpty(procID)
	msgID := "DNSQUERY"

	// Values are escaped with escapeSD and wrapped in literal double quotes.
	// Do not use %q here: it would double-escape the already-escaped values.
	sd := fmt.Sprintf(
		`[%s domain="%s" client="%s" action="%s" suspicious="%s" score="%s" method="%s" reason="%s"]`,
		syslogSDID,
		escapeSD(ev.Domain),
		escapeSD(ev.ClientIP),
		escapeSD(ev.Action),
		strconv.FormatBool(ev.IsSuspicious),
		strconv.FormatFloat(ev.ThreatScore, 'f', 2, 64),
		escapeSD(ev.DetectionMethod),
		escapeSD(ev.ThreatReason),
	)

	msg := fmt.Sprintf("dns query domain=%s client=%s action=%s", ev.Domain, ev.ClientIP, ev.Action)

	return fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		pri, ts, hostname, appName, procID, msgID, sd, msg)
}

func nilIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// escapeSD escapes the three characters RFC 5424 requires to be escaped inside
// a structured-data PARAM-VALUE: '"', '\', and ']'.
func escapeSD(s string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`]`, `\]`,
	).Replace(s)
}

// --- webhook sink (POST JSON) ---

type webhookSink struct {
	url    string
	client *http.Client
}

func newWebhookSink(target string) *webhookSink {
	return &webhookSink{
		url: target,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (h *webhookSink) Send(ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hydradns-exporter")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("post webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func (h *webhookSink) Close() error { return nil }
