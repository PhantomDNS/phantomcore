// SPDX-License-Identifier: GPL-3.0-or-later
package nrd

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/lopster568/phantomDNS/internal/blocklist/fetcher"
	"github.com/lopster568/phantomDNS/internal/blocklist/parser"
	"github.com/lopster568/phantomDNS/internal/logger"
)

const (
	defaultRefreshInterval = 6 * time.Hour
	// defaultFormat is the parser format used for NRD feeds. Feeds are typically
	// one registrable domain per line, handled by the "domains" parser.
	defaultFormat = "domains"
)

// Config controls NRD feed behavior. A zero Config (empty FeedURL) is inert.
type Config struct {
	// FeedURL is the operator-configured URL of the newly-registered-domain feed.
	// Empty disables NRD entirely.
	FeedURL string
	// Block reports whether listed domains are blocked (true) or only flagged
	// (false). Defaults to false (flag) to fail open.
	Block bool
	// RefreshInterval is how often the feed is re-fetched. Defaults to 6h.
	RefreshInterval time.Duration
	// Format selects the parser used for the feed body. Defaults to "domains".
	Format string
}

// Checker holds the current NRD set and refreshes it from the configured feed.
// It reuses the blocklist fetcher (ETag/conditional-GET) and parser registry but
// keeps its set entirely separate from user blocklists. The zero value is not
// usable; construct with New or NewWithSet.
type Checker struct {
	cfg     Config
	fetcher *fetcher.HTTPFetcher
	set     atomic.Pointer[Set]
	etag    atomic.Pointer[string]
}

// New constructs a Checker from cfg, applying defaults for the refresh interval
// and feed format. The checker starts with an empty set and is inert until the
// feed is refreshed. When FeedURL is empty the checker stays permanently inert.
func New(cfg Config) *Checker {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = defaultRefreshInterval
	}
	if cfg.Format == "" {
		cfg.Format = defaultFormat
	}
	c := &Checker{cfg: cfg, fetcher: fetcher.NewHTTPFetcher()}
	c.set.Store(NewSet(nil))
	return c
}

// NewWithSet builds a Checker backed by a fixed set. It performs no fetching and
// is intended for tests and manual wiring.
func NewWithSet(set *Set, block bool) *Checker {
	c := New(Config{Block: block})
	if set == nil {
		set = NewSet(nil)
	}
	c.set.Store(set)
	return c
}

// Enabled reports whether a feed URL is configured.
func (c *Checker) Enabled() bool {
	return c != nil && c.cfg.FeedURL != ""
}

// BlockMode reports whether listed domains should be blocked (true) or flagged
// (false).
func (c *Checker) BlockMode() bool {
	return c != nil && c.cfg.Block
}

// IsListed reports whether the domain or its registrable parent is on the feed.
// It is inert (always false) when no feed data has been loaded.
func (c *Checker) IsListed(domain string) bool {
	if c == nil {
		return false
	}
	return c.set.Load().Contains(domain)
}

// Len reports the number of domains currently loaded from the feed.
func (c *Checker) Len() int {
	if c == nil {
		return 0
	}
	return c.set.Load().Len()
}

// load parses a raw feed body and atomically swaps in the resulting set.
func (c *Checker) load(data []byte) error {
	p, ok := parser.Get(c.cfg.Format)
	if !ok {
		return fmt.Errorf("nrd: no parser for format %q", c.cfg.Format)
	}
	entries, err := p.Parse(data)
	if err != nil {
		return fmt.Errorf("nrd: parse feed: %w", err)
	}
	domains := make([]string, len(entries))
	for i, e := range entries {
		domains[i] = e.Domain
	}
	c.set.Store(NewSet(domains))
	return nil
}

// Refresh fetches the feed once and swaps in the new set. It honors ETag /
// If-None-Match: a 304 response leaves the current set untouched. It is a no-op
// when no feed is configured.
func (c *Checker) Refresh(ctx context.Context) error {
	if !c.Enabled() {
		return nil
	}

	knownETag := ""
	if p := c.etag.Load(); p != nil {
		knownETag = *p
	}

	src := parser.SourceConfig{
		ID:     "nrd",
		Name:   "nrd-feed",
		URL:    c.cfg.FeedURL,
		Format: c.cfg.Format,
	}
	body, etag, err := c.fetcher.Fetch(ctx, src, knownETag)
	if err != nil {
		return fmt.Errorf("nrd: fetch feed: %w", err)
	}
	if body == nil {
		// Not modified; keep the existing set.
		return nil
	}
	if err := c.load(body); err != nil {
		return err
	}
	c.etag.Store(&etag)
	logger.Log.Infof("NRD feed refreshed: %d domains (block=%v)", c.Len(), c.cfg.Block)
	return nil
}

// Run performs an initial refresh and then re-fetches on RefreshInterval until
// ctx is cancelled. It returns immediately when no feed is configured.
func (c *Checker) Run(ctx context.Context) {
	if !c.Enabled() {
		return
	}
	if err := c.Refresh(ctx); err != nil {
		logger.Log.Errorf("initial NRD feed refresh failed: %v", err)
	}

	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			if err := c.Refresh(rctx); err != nil {
				logger.Log.Errorf("NRD feed refresh failed: %v", err)
			}
			cancel()
		}
	}
}
