// SPDX-License-Identifier: GPL-3.0-or-later
package parser

import (
	"bufio"
	"bytes"
	"strings"
	"time"
)

// DomainsParser parses feeds with one domain per line. Blank lines and lines
// beginning with '#' or ';' are ignored. Only the first whitespace-separated
// field of each line is used, so simple "domain <extra>" columns are tolerated.
// A leading "*." wildcard and a trailing dot are stripped. This format suits
// plain domain lists such as newly-registered-domain (NRD) feeds.
type DomainsParser struct{}

func (d *DomainsParser) Format() string { return "domains" }

func (d *DomainsParser) Parse(data []byte) ([]ParsedEntry, error) {
	s := bufio.NewScanner(bytes.NewReader(data))
	var out []ParsedEntry
	now := time.Now()
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			line = line[:idx]
		}
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "*."), "."))
		if domain == "" {
			continue
		}
		out = append(out, ParsedEntry{
			Domain:  domain,
			Fetched: now,
		})
	}
	return out, s.Err()
}

func init() {
	Register(&DomainsParser{})
}
