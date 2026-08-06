// SPDX-License-Identifier: GPL-3.0-or-later

// Package whatsapp implements a notification sink backed by the Meta WhatsApp
// Business Cloud API. It lets alert and report paths deliver messages over
// WhatsApp by POSTing to https://graph.facebook.com/v.../{phone_number_id}/messages
// with a bearer token.
//
// SCAFFOLDING: this integration is disabled by default and completely inert
// until credentials are supplied. Actually delivering messages requires an
// approved WhatsApp Business Account (WABA) and, for template messages, a
// pre-approved message template. Until that approval is in place the notifier
// is a no-op. The package is therefore fully unit-tested against a local
// httptest server rather than the live Meta API.
//
// Configuration comes from three environment variables; if any is empty the
// notifier is disabled and Notify does nothing:
//
//	WHATSAPP_TOKEN     bearer token for the WhatsApp Cloud API
//	WHATSAPP_PHONE_ID  sender phone number ID
//	WHATSAPP_TO        recipient phone number in E.164 form
package whatsapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// defaultAPIVersion is the Graph API version segment used when none is set.
	defaultAPIVersion = "v20.0"
	// defaultBaseURL is the Meta Graph API host. Overridable for testing.
	defaultBaseURL = "https://graph.facebook.com"
	// defaultTimeout bounds a single delivery attempt.
	defaultTimeout = 10 * time.Second
	// maxErrBody caps how much of an error response body we read back.
	maxErrBody = 4096
)

// Notifier is the minimal contract alert and report paths use to send an
// outbound message. Implementations must be safe for concurrent use and must
// treat a disabled/unconfigured sink as a successful no-op.
type Notifier interface {
	// Notify sends a plain-text message. When the sink is disabled it returns
	// nil without performing any I/O.
	Notify(ctx context.Context, message string) error
	// Enabled reports whether the notifier will actually deliver messages.
	Enabled() bool
}

// Config holds the credentials and target for the WhatsApp Cloud API. All of
// Token, PhoneID and To must be set for the notifier to be enabled; if any is
// empty the notifier is a no-op.
type Config struct {
	Token   string // WHATSAPP_TOKEN
	PhoneID string // WHATSAPP_PHONE_ID
	To      string // WHATSAPP_TO

	// APIVersion is the Graph API version segment, e.g. "v20.0". Defaults to
	// defaultAPIVersion when empty.
	APIVersion string
	// BaseURL is the API host. Defaults to defaultBaseURL when empty. This is
	// primarily an injection point for tests.
	BaseURL string
}

// ConfigFromEnv builds a Config from WHATSAPP_TOKEN, WHATSAPP_PHONE_ID and
// WHATSAPP_TO. When any of them is absent the resulting notifier is disabled.
func ConfigFromEnv() Config {
	return Config{
		Token:   os.Getenv("WHATSAPP_TOKEN"),
		PhoneID: os.Getenv("WHATSAPP_PHONE_ID"),
		To:      os.Getenv("WHATSAPP_TO"),
	}
}

// Enabled reports whether all required credentials are present.
func (c Config) Enabled() bool {
	return c.Token != "" && c.PhoneID != "" && c.To != ""
}

// Client is a WhatsApp Cloud API Notifier. Construct one with New or
// NewFromEnv; the zero value is not usable.
type Client struct {
	cfg  Config
	http *http.Client
}

// Compile-time assurance that *Client satisfies Notifier.
var _ Notifier = (*Client)(nil)

// New constructs a Client from cfg. When cfg is missing credentials the
// returned Client is a valid no-op: Enabled reports false and Notify does
// nothing. httpClient may be nil, in which case a client with a sane timeout
// is used.
func New(cfg Config, httpClient *http.Client) *Client {
	if cfg.APIVersion == "" {
		cfg.APIVersion = defaultAPIVersion
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{cfg: cfg, http: httpClient}
}

// NewFromEnv constructs a Client from environment variables. It never returns
// an error: with no credentials configured the returned Client is a no-op,
// which is the default (disabled) state pending WABA approval.
func NewFromEnv() *Client {
	return New(ConfigFromEnv(), nil)
}

// Enabled reports whether the client will actually deliver messages.
func (c *Client) Enabled() bool {
	return c.cfg.Enabled()
}

// endpoint returns the fully-qualified messages endpoint for the configured
// phone number ID.
func (c *Client) endpoint() string {
	return fmt.Sprintf("%s/%s/%s/messages",
		strings.TrimRight(c.cfg.BaseURL, "/"),
		c.cfg.APIVersion,
		c.cfg.PhoneID,
	)
}

// --- request payload types -------------------------------------------------

type textBody struct {
	PreviewURL bool   `json:"preview_url"`
	Body       string `json:"body"`
}

type templateLanguage struct {
	Code string `json:"code"`
}

type templateParameter struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type templateComponent struct {
	Type       string              `json:"type"`
	Parameters []templateParameter `json:"parameters,omitempty"`
}

type templatePayload struct {
	Name       string              `json:"name"`
	Language   templateLanguage    `json:"language"`
	Components []templateComponent `json:"components,omitempty"`
}

// message is the Cloud API /messages request body.
type message struct {
	MessagingProduct string           `json:"messaging_product"`
	RecipientType    string           `json:"recipient_type,omitempty"`
	To               string           `json:"to"`
	Type             string           `json:"type"`
	Text             *textBody        `json:"text,omitempty"`
	Template         *templatePayload `json:"template,omitempty"`
}

// buildTextMessage assembles the request body for a plain-text message to the
// configured recipient.
func (c *Client) buildTextMessage(body string) message {
	return message{
		MessagingProduct: "whatsapp",
		RecipientType:    "individual",
		To:               c.cfg.To,
		Type:             "text",
		Text:             &textBody{PreviewURL: false, Body: body},
	}
}

// buildTemplateMessage assembles the request body for a pre-approved template
// message. langCode defaults to "en_US" when empty; bodyParams, when present,
// are attached as text parameters of the template body component.
func (c *Client) buildTemplateMessage(name, langCode string, bodyParams []string) message {
	if langCode == "" {
		langCode = "en_US"
	}
	tpl := &templatePayload{
		Name:     name,
		Language: templateLanguage{Code: langCode},
	}
	if len(bodyParams) > 0 {
		params := make([]templateParameter, 0, len(bodyParams))
		for _, p := range bodyParams {
			params = append(params, templateParameter{Type: "text", Text: p})
		}
		tpl.Components = []templateComponent{{Type: "body", Parameters: params}}
	}
	return message{
		MessagingProduct: "whatsapp",
		To:               c.cfg.To,
		Type:             "template",
		Template:         tpl,
	}
}

// --- delivery --------------------------------------------------------------

// Notify sends msg as a WhatsApp text message. If the client is disabled
// (missing credentials) it is a no-op and returns nil.
func (c *Client) Notify(ctx context.Context, msg string) error {
	if !c.Enabled() {
		return nil
	}
	if strings.TrimSpace(msg) == "" {
		return fmt.Errorf("whatsapp: empty message")
	}
	return c.post(ctx, c.buildTextMessage(msg))
}

// NotifyTemplate sends a pre-approved template message. If the client is
// disabled it is a no-op and returns nil. This is the delivery path a real
// WABA integration uses once a template has been approved by Meta.
func (c *Client) NotifyTemplate(ctx context.Context, name, langCode string, bodyParams ...string) error {
	if !c.Enabled() {
		return nil
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("whatsapp: empty template name")
	}
	return c.post(ctx, c.buildTemplateMessage(name, langCode, bodyParams))
}

// post marshals m and POSTs it to the messages endpoint with the bearer token.
func (c *Client) post(ctx context.Context, m message) error {
	payload, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("whatsapp: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("whatsapp: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("whatsapp: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		return fmt.Errorf("whatsapp: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Drain the body so the underlying connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
	return nil
}
