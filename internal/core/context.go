package core

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// QueryContext holds all metadata about a DNS query
// as it flows through the pipeline.
// to be used later during refactor
type QueryContext struct {
	// Raw DNS request & response
	Request  *dns.Msg
	Response *dns.Msg

	// Networking info
	ClientAddr net.Addr  // Who sent the query
	Protocol   string    // udp / tcp / dot / doh
	ReceivedAt time.Time // when we got it

	// Policy-related metadata
	PolicyMatched string   // e.g., "block:ads"
	BlockReason   string   // why it was blocked
	Tags          []string // arbitrary labels (e.g., "malware", "family-safe")

	// Upstream resolution
	Upstream       string        // chosen upstream server
	ResolutionTime time.Duration // time taken to resolve

	// Internal tracing
	ID string // request ID for logs/tracing
}
