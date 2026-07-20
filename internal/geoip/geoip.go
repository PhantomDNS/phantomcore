// SPDX-License-Identifier: GPL-3.0-or-later

// Package geoip implements optional ASN/GeoIP-based answer filtering.
//
// When an operator supplies a MaxMind-format database, the IPs an upstream
// resolver returns in an answer can be checked against a configured set of
// blocked ASNs or ISO country codes and either flagged (marked suspicious but
// still returned) or blocked. Flag-only is the default because CDN address
// space frequently spans many ASNs/countries and outright blocking risks
// false positives.
//
// The whole package is inert when no database is configured: FromConfig
// returns a nil *Filter, and every *Filter method is nil-safe, so callers pay
// zero overhead on the hot path.
package geoip

import (
	"net"
	"strconv"
	"strings"
)

// Resolver looks up the ASN and ISO country code for an IP address.
//
// It is deliberately tiny so tests can supply a hermetic mock instead of a
// real .mmdb file. The maxminddb-backed implementation lives in maxmind.go and
// is constructed only when a database path is provided.
type Resolver interface {
	Lookup(ip net.IP) (asn uint, country string, err error)
}

// Decision is the outcome of evaluating a set of answer IPs against a Filter.
// The zero value (Matched == false) means "nothing to do".
type Decision struct {
	Matched bool   // an answer IP fell in a blocked ASN or country
	Block   bool   // true = block the response; false = flag only
	IP      string // the offending answer IP
	ASN     uint   // matched ASN (0 when the match was by country)
	Country string // matched ISO country code (empty when matched by ASN)
	Reason  string // human-readable explanation, suitable for logs
}

// Filter evaluates answer IPs against blocked ASNs and country codes.
//
// A nil *Filter is inert: every method short-circuits, so callers can treat a
// nil filter as "GeoIP filtering disabled" without a guard.
type Filter struct {
	resolver         Resolver
	blockedASNs      map[uint]struct{}
	blockedCountries map[string]struct{}
	block            bool
}

// NewFilter builds a Filter from an already-constructed Resolver.
//
// It returns nil when there is nothing to enforce — no resolver, or no blocked
// ASNs and no blocked countries — so an operator who sets a DB path but no
// block lists still gets a zero-overhead inert filter.
func NewFilter(resolver Resolver, blockedASNs []uint, blockedCountries []string, block bool) *Filter {
	if resolver == nil {
		return nil
	}

	asns := make(map[uint]struct{}, len(blockedASNs))
	for _, a := range blockedASNs {
		asns[a] = struct{}{}
	}

	countries := make(map[string]struct{}, len(blockedCountries))
	for _, c := range blockedCountries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			countries[c] = struct{}{}
		}
	}

	if len(asns) == 0 && len(countries) == 0 {
		return nil
	}

	return &Filter{
		resolver:         resolver,
		blockedASNs:      asns,
		blockedCountries: countries,
		block:            block,
	}
}

// BlockMode reports whether a match should block the response (true) or only
// flag it as suspicious (false). Nil-safe.
func (f *Filter) BlockMode() bool {
	if f == nil {
		return false
	}
	return f.block
}

// Evaluate looks up each answer IP and returns the first match against a
// blocked ASN or country. A nil filter, an empty IP list, or no matches all
// yield the zero Decision (Matched == false).
//
// Lookup errors are treated as a miss and skipped: answer filtering runs on
// the allow path after a successful upstream response, so a database gap must
// never fail the query closed.
func (f *Filter) Evaluate(ips []net.IP) Decision {
	if f == nil {
		return Decision{}
	}

	for _, ip := range ips {
		if ip == nil {
			continue
		}

		asn, country, err := f.resolver.Lookup(ip)
		if err != nil {
			continue
		}

		// ASN 0 is "unknown" in MaxMind data; never let an unknown IP match a
		// configured block on ASN 0.
		if asn != 0 {
			if _, ok := f.blockedASNs[asn]; ok {
				return Decision{
					Matched: true,
					Block:   f.block,
					IP:      ip.String(),
					ASN:     asn,
					Reason:  "answer IP " + ip.String() + " in blocked ASN " + strconv.FormatUint(uint64(asn), 10),
				}
			}
		}

		country = strings.ToUpper(country)
		if country != "" {
			if _, ok := f.blockedCountries[country]; ok {
				return Decision{
					Matched: true,
					Block:   f.block,
					IP:      ip.String(),
					Country: country,
					Reason:  "answer IP " + ip.String() + " in blocked country " + country,
				}
			}
		}
	}

	return Decision{}
}
