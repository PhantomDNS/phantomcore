// SPDX-License-Identifier: GPL-3.0-or-later

// Package bundle provides an offline-first default blocklist that is embedded
// directly into the dataplane binary. It lets DNS filtering work from the very
// first boot with no internet connectivity: on startup, if the database has no
// blocklist snapshot yet, the dataplane seeds itself from this bundle so the
// checker blocks immediately. The normal periodic refresh then augments/replaces
// coverage from the configured upstream sources once the device is online.
package bundle

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"

	"github.com/lopster568/phantomDNS/internal/blocklist/parser"
)

// Format is the on-disk format of the embedded bundle and the parser used to
// decode it. It is intentionally the same "hosts" format the online sources use
// so the exact same parser handles both paths.
const Format = "hosts"

//go:embed default_hosts.txt
var content embed.FS

const bundleFile = "default_hosts.txt"

// Raw returns the raw bytes of the embedded bundle.
func Raw() ([]byte, error) {
	return content.ReadFile(bundleFile)
}

// Checksum returns a stable hex SHA-256 of the embedded bundle. It is used as
// the snapshot checksum when seeding so a re-seed of identical content is
// recognisable and deterministic.
func Checksum() (string, error) {
	raw, err := Raw()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Load parses the embedded bundle using the registered hosts parser and returns
// the parsed entries. It reuses the exact same parser as the online fetch path,
// so bundled and fetched data are normalised identically.
func Load() ([]parser.ParsedEntry, error) {
	p, ok := parser.Get(Format)
	if !ok {
		return nil, errors.New("bundle: hosts parser not registered")
	}
	raw, err := Raw()
	if err != nil {
		return nil, err
	}
	return p.Parse(raw)
}

// Domains parses the embedded bundle and returns just the normalised domain
// strings. Provided as a convenience for callers/tests that do not need the
// full ParsedEntry.
func Domains() ([]string, error) {
	entries, err := Load()
	if err != nil {
		return nil, err
	}
	domains := make([]string, len(entries))
	for i, e := range entries {
		domains[i] = e.Domain
	}
	return domains, nil
}
