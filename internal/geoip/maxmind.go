// SPDX-License-Identifier: GPL-3.0-or-later

package geoip

import (
	"fmt"
	"net"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// maxmindResolver is a Resolver backed by a MaxMind-format database.
type maxmindResolver struct {
	db *maxminddb.Reader
}

// mmRecord is the subset of MaxMind record fields we read. It is intentionally
// permissive: a GeoLite2-Country DB populates country.iso_code, a GeoLite2-ASN
// DB populates autonomous_system_number, and combined databases populate both.
// Absent fields decode to their zero value.
type mmRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
}

// NewMaxMindResolver opens the MaxMind database at path.
//
// This is the only code that touches a real .mmdb file; construct it solely
// when a database path is configured (see FromConfig).
func NewMaxMindResolver(path string) (Resolver, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %q: %w", path, err)
	}
	return &maxmindResolver{db: db}, nil
}

// Lookup implements Resolver. A country from the main "country" record is
// preferred, falling back to "registered_country" when the former is absent.
func (m *maxmindResolver) Lookup(ip net.IP) (uint, string, error) {
	var rec mmRecord
	if err := m.db.Lookup(ip, &rec); err != nil {
		return 0, "", err
	}
	country := rec.Country.ISOCode
	if country == "" {
		country = rec.RegisteredCountry.ISOCode
	}
	return rec.AutonomousSystemNumber, country, nil
}

// Close releases the underlying database handle.
func (m *maxmindResolver) Close() error {
	return m.db.Close()
}

// FromConfig builds a Filter from resolved configuration values.
//
// It opens the MaxMind database only when path is non-empty. When path is empty
// it returns (nil, nil): GeoIP filtering is disabled and the caller gets a
// zero-overhead inert filter. An error is returned only when a configured
// database fails to open.
func FromConfig(path string, blockedASNs []uint, blockedCountries []string, block bool) (*Filter, error) {
	if path == "" {
		return nil, nil
	}
	resolver, err := NewMaxMindResolver(path)
	if err != nil {
		return nil, err
	}
	return NewFilter(resolver, blockedASNs, blockedCountries, block), nil
}
