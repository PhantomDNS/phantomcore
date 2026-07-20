// SPDX-License-Identifier: GPL-3.0-or-later

package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
)

// webhookTimeout bounds how long a single alert POST may take.
const webhookTimeout = 5 * time.Second

// NewWebhookSink returns an alert sink that POSTs the alert as JSON to url. The
// POST runs in its own goroutine so alerting never blocks the DNS path; failures
// are logged and dropped. An empty url yields a nil sink (no-op).
func NewWebhookSink(url string) func(Alert) {
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: webhookTimeout}
	return func(a Alert) {
		go postAlert(client, url, a)
	}
}

func postAlert(client *http.Client, url string, a Alert) {
	body, err := json.Marshal(a)
	if err != nil {
		logger.Log.Errorf("alert webhook: marshal failed: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logger.Log.Errorf("alert webhook: build request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		logger.Log.Errorf("alert webhook: POST %s failed: %v", url, err)
		return
	}
	_ = resp.Body.Close()
}
