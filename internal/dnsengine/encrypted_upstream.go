// DoT (DNS-over-TLS) and DoH (DNS-over-HTTPS) upstream transports.
// SPDX-License-Identifier: GPL-3.0-or-later
package dnsengine

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// Compile-time assertions that every transport satisfies Upstream.
var (
	_ Upstream = (*UpstreamPool)(nil)
	_ Upstream = (*dotClient)(nil)
	_ Upstream = (*dohClient)(nil)
)

// dohContentType is the media type mandated by RFC 8484 for wire-format DNS.
const dohContentType = "application/dns-message"

// dotClient implements Upstream using DNS-over-TLS (RFC 7858) via the
// miekg/dns TLS client ("tcp-tls").
type dotClient struct {
	addr   string
	client *dns.Client
}

// newDoTClient builds a DoT client for a host:port address (e.g. 1.1.1.1:853).
func newDoTClient(addr string) (*dotClient, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid DoT address %q: %w", addr, err)
	}
	return &dotClient{
		addr: addr,
		client: &dns.Client{
			Net:     "tcp-tls",
			Timeout: defaultQueryTimeout,
			TLSConfig: &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			},
		},
	}, nil
}

// Exchange sends q over the DoT client. The timeout argument is accepted for
// interface parity with the plain path (which likewise applies a fixed query
// timeout); DoT uses the client's configured timeout.
func (d *dotClient) Exchange(q *dns.Msg, _ time.Duration) (*dns.Msg, error) {
	resp, _, err := d.client.Exchange(q, d.addr)
	if err != nil {
		return nil, fmt.Errorf("dot exchange to %s: %w", d.addr, err)
	}
	return resp, nil
}

func (d *dotClient) Close() error { return nil }

func (d *dotClient) Addr() string { return "tls://" + d.addr }

// dohClient implements Upstream using DNS-over-HTTPS (RFC 8484). Queries are
// POSTed as application/dns-message and the response body is the wire-format
// reply.
type dohClient struct {
	endpoint string
	client   *http.Client
}

// newDoHClient builds a DoH client for a full https endpoint URL
// (e.g. https://cloudflare-dns.com/dns-query).
func newDoHClient(endpoint string) (*dohClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("DoH endpoint must use https: %q", endpoint)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("DoH endpoint missing host: %q", endpoint)
	}
	return &dohClient{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: defaultQueryTimeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: true,
			},
		},
	}, nil
}

// Exchange packs q, POSTs it to the DoH endpoint per RFC 8484, and unpacks the
// wire-format response. The timeout argument is accepted for interface parity;
// the request is bounded by the HTTP client's configured timeout.
func (d *dohClient) Exchange(q *dns.Msg, _ time.Duration) (*dns.Msg, error) {
	packed, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh pack query: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, d.endpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("doh build request: %w", err)
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh exchange to %s: %w", d.endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort; body is fully drained below or discarded on non-2xx

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("doh unexpected status %d from %s", resp.StatusCode, d.endpoint)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("doh read response: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh unpack response: %w", err)
	}
	return out, nil
}

func (d *dohClient) Close() error {
	d.client.CloseIdleConnections()
	return nil
}

func (d *dohClient) Addr() string { return d.endpoint }
