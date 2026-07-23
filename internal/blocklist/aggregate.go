// SPDX-License-Identifier: GPL-3.0-or-later
package blocklist

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lopster568/phantomDNS/internal/blocklist/parser"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/storage/models"
)

// aggregateFormat marks a blocklist source whose entries were produced by aggregating a
// category's feeds or a collection's bundle, rather than by fetching a single raw list.
const aggregateFormat = "aggregate"

// AggregateFeeds fetches every feed for a category, parses each through the registered
// parser for its format, dedups the resulting domains across all feeds, and stores them
// under a single aggregated blocklist source (sourceID). It reuses the same
// fetch/parse/store engine that individual blocklist sources use.
//
// Individual feed failures are tolerated: a single unreachable feed is logged and
// skipped so one dead mirror does not disable a whole category. An error is returned
// only when nothing could be aggregated (every feed failed).
func (e *Engine) AggregateFeeds(ctx context.Context, sourceID, sourceName, category string, feeds []Feed) (int, error) {
	seen := make(map[string]struct{})
	var entries []models.BlocklistEntry
	now := time.Now()

	var lastErr error
	fetched := 0
	for _, f := range feeds {
		body, _, err := e.fetcher.Fetch(ctx, feedConfig(f), "")
		if err != nil {
			logger.Log.Warnf("category %s: feed %q fetch failed: %v", category, f.Name, err)
			lastErr = err
			continue
		}
		if body == nil { // 304 Not Modified — nothing to add.
			fetched++
			continue
		}
		p, ok := parser.Get(f.Format)
		if !ok {
			lastErr = fmt.Errorf("no parser for format %q (feed %q)", f.Format, f.Name)
			logger.Log.Warnf("category %s: %v", category, lastErr)
			continue
		}
		parsed, err := p.Parse(body)
		if err != nil {
			logger.Log.Warnf("category %s: feed %q parse failed: %v", category, f.Name, err)
			lastErr = err
			continue
		}
		fetched++
		for _, pe := range parsed {
			d := normalizeDomain(pe.Domain)
			if d == "" {
				continue
			}
			if _, dup := seen[d]; dup {
				continue
			}
			seen[d] = struct{}{}
			entries = append(entries, models.BlocklistEntry{
				Domain:    d,
				SourceID:  sourceID,
				Category:  category,
				CreatedAt: now,
			})
		}
	}

	if fetched == 0 && lastErr != nil {
		return 0, fmt.Errorf("category %s: all feeds failed: %w", category, lastErr)
	}

	if err := e.storeAggregate(sourceID, sourceName, category, entries); err != nil {
		return 0, err
	}
	logger.Log.Infof("aggregated category=%s feeds=%d domains=%d", category, len(feeds), len(entries))
	return len(entries), nil
}

// StoreDomains stores a curated, inline domain bundle (an app/service collection, I-052)
// under an aggregated blocklist source. Domains are deduped and normalized. No network
// fetch happens — the bundle is defined in the catalog.
func (e *Engine) StoreDomains(sourceID, sourceName, category string, domains []string) (int, error) {
	seen := make(map[string]struct{})
	var entries []models.BlocklistEntry
	now := time.Now()
	for _, raw := range domains {
		d := normalizeDomain(raw)
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		entries = append(entries, models.BlocklistEntry{
			Domain:    d,
			SourceID:  sourceID,
			Category:  category,
			CreatedAt: now,
		})
	}
	if err := e.storeAggregate(sourceID, sourceName, category, entries); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// storeAggregate persists the aggregated entries under an (upserted) aggregate source
// row via the existing snapshot/entries writer, so the dataplane's live blocklist view
// picks the domains up immediately.
func (e *Engine) storeAggregate(sourceID, sourceName, category string, entries []models.BlocklistEntry) error {
	src := models.BlocklistSource{
		ID:        sourceID,
		Name:      sourceName,
		Category:  category,
		Format:    aggregateFormat,
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	if _, err := e.repo.SaveSnapshotWithEntries(src, hash([]byte(sourceID+category)), entries); err != nil {
		return fmt.Errorf("store aggregate %s failed: %w", sourceID, err)
	}
	return nil
}

// normalizeDomain lowercases, trims whitespace and a trailing dot, and rejects tokens
// that are clearly not bare domains.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	if d == "" || strings.ContainsAny(d, "/\\ ") {
		return ""
	}
	return d
}

// feedConfig adapts a catalog Feed to the fetcher/parser SourceConfig shape.
func feedConfig(f Feed) parser.SourceConfig {
	return parser.SourceConfig{
		Name:   f.Name,
		URL:    f.URL,
		Format: f.Format,
	}
}
