package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/lopster568/phantomDNS/internal/blocklist/parser"
)

type HTTPFetcher struct {
	client *http.Client
}

func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Fetch returns body bytes, etag string, and error.
//
// Custody note (LOCAL_ONLY / I-061): this outbound request is ALLOWED even
// under LOCAL_ONLY. Pulling operator-configured blocklist sources is a core
// filtering function, not a phone-home, so it is intentionally NOT gated by
// config.LocalOnly(). See internal/config/local_only.go for the contract.
func (h *HTTPFetcher) Fetch(ctx context.Context, src parser.SourceConfig, knownETag string) ([]byte, string, error) {
	var body []byte
	var etag string

	op := func() error {
		req, _ := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
		if knownETag != "" {
			req.Header.Set("If-None-Match", knownETag)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotModified {
			// nothing changed
			etag = knownETag
			body = nil
			return nil
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("http status %d", resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		etag = resp.Header.Get("ETag")
		body = b
		return nil
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 2 * time.Minute
	// Wrap the caller's context so retries stop as soon as it is canceled or
	// its deadline expires, instead of running the full backoff schedule (up
	// to MaxElapsedTime) regardless of the caller's own timeout. Without this,
	// a dead feed retried for close to 2 minutes even when the caller asked
	// for a much shorter timeout.
	if err := backoff.Retry(op, backoff.WithContext(bo, ctx)); err != nil {
		return nil, "", err
	}
	return body, etag, nil
}
