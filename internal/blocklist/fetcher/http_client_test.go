// SPDX-License-Identifier: GPL-3.0-or-later
package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/blocklist/parser"
)

// TestFetch_HonorsCallerContextTimeout guards against a regression where
// backoff.Retry ran the full exponential-backoff schedule (up to
// bo.MaxElapsedTime, ~2 minutes) regardless of the caller's own context
// deadline. A dead/erroring feed must stop retrying as soon as the caller's
// context is done, not run for the backoff's own full budget.
func TestFetch_HonorsCallerContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always fail so the retry loop keeps going until the context (or the
		// backoff budget) gives up.
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	h := NewHTTPFetcher()
	src := parser.SourceConfig{ID: "test", URL: srv.URL, Enabled: true}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := h.Fetch(ctx, src, "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a permanently-failing feed")
	}
	// Give generous headroom over the 300ms deadline for scheduling jitter,
	// but this must be nowhere near the 2-minute backoff MaxElapsedTime that
	// the bug would otherwise run for.
	if elapsed > 5*time.Second {
		t.Fatalf("Fetch ignored the caller's context deadline: took %s (expected well under 5s)", elapsed)
	}
}
