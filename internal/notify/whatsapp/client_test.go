// SPDX-License-Identifier: GPL-3.0-or-later

package whatsapp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func enabledConfig() Config {
	return Config{
		Token:   "test-token",
		PhoneID: "1234567890",
		To:      "919999999999",
	}
}

func TestConfigEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"all set", Config{Token: "t", PhoneID: "p", To: "r"}, true},
		{"empty", Config{}, false},
		{"missing token", Config{PhoneID: "p", To: "r"}, false},
		{"missing phone", Config{Token: "t", To: "r"}, false},
		{"missing to", Config{Token: "t", PhoneID: "p"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.Enabled(); got != tt.want {
				t.Errorf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("WHATSAPP_TOKEN", "env-token")
	t.Setenv("WHATSAPP_PHONE_ID", "env-phone")
	t.Setenv("WHATSAPP_TO", "env-to")

	cfg := ConfigFromEnv()
	if cfg.Token != "env-token" || cfg.PhoneID != "env-phone" || cfg.To != "env-to" {
		t.Fatalf("ConfigFromEnv() = %+v, want values from env", cfg)
	}
	if !cfg.Enabled() {
		t.Errorf("Enabled() = false, want true")
	}
}

func TestNewFromEnv_DisabledWithoutCreds(t *testing.T) {
	t.Setenv("WHATSAPP_TOKEN", "")
	t.Setenv("WHATSAPP_PHONE_ID", "")
	t.Setenv("WHATSAPP_TO", "")

	c := NewFromEnv()
	if c.Enabled() {
		t.Errorf("Enabled() = true, want false when no creds set")
	}
}

func TestEndpoint(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "defaults version",
			cfg:  Config{PhoneID: "111", BaseURL: "https://graph.facebook.com"},
			want: "https://graph.facebook.com/" + defaultAPIVersion + "/111/messages",
		},
		{
			name: "explicit version",
			cfg:  Config{PhoneID: "222", APIVersion: "v21.0", BaseURL: "https://example.test"},
			want: "https://example.test/v21.0/222/messages",
		},
		{
			name: "trims trailing slash on base url",
			cfg:  Config{PhoneID: "333", APIVersion: "v20.0", BaseURL: "https://example.test/"},
			want: "https://example.test/v20.0/333/messages",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.cfg, nil)
			if got := c.endpoint(); got != tt.want {
				t.Errorf("endpoint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildTextMessage(t *testing.T) {
	c := New(enabledConfig(), nil)
	m := c.buildTextMessage("hello world")

	if m.MessagingProduct != "whatsapp" {
		t.Errorf("MessagingProduct = %q, want whatsapp", m.MessagingProduct)
	}
	if m.RecipientType != "individual" {
		t.Errorf("RecipientType = %q, want individual", m.RecipientType)
	}
	if m.To != "919999999999" {
		t.Errorf("To = %q, want 919999999999", m.To)
	}
	if m.Type != "text" {
		t.Errorf("Type = %q, want text", m.Type)
	}
	if m.Text == nil || m.Text.Body != "hello world" {
		t.Errorf("Text = %+v, want body 'hello world'", m.Text)
	}
	if m.Template != nil {
		t.Errorf("Template = %+v, want nil for a text message", m.Template)
	}
}

func TestBuildTemplateMessage(t *testing.T) {
	c := New(enabledConfig(), nil)

	// No language -> default en_US, no params -> no components.
	m := c.buildTemplateMessage("alert_tpl", "", nil)
	if m.Type != "template" {
		t.Fatalf("Type = %q, want template", m.Type)
	}
	if m.Template == nil {
		t.Fatalf("Template = nil, want non-nil")
	}
	if m.Template.Name != "alert_tpl" {
		t.Errorf("Template.Name = %q, want alert_tpl", m.Template.Name)
	}
	if m.Template.Language.Code != "en_US" {
		t.Errorf("Language.Code = %q, want en_US (default)", m.Template.Language.Code)
	}
	if len(m.Template.Components) != 0 {
		t.Errorf("Components = %+v, want empty", m.Template.Components)
	}

	// Explicit language + body params -> body component with text params.
	m2 := c.buildTemplateMessage("report_tpl", "en", []string{"one", "two"})
	if m2.Template.Language.Code != "en" {
		t.Errorf("Language.Code = %q, want en", m2.Template.Language.Code)
	}
	if len(m2.Template.Components) != 1 {
		t.Fatalf("Components len = %d, want 1", len(m2.Template.Components))
	}
	comp := m2.Template.Components[0]
	if comp.Type != "body" {
		t.Errorf("Component.Type = %q, want body", comp.Type)
	}
	if len(comp.Parameters) != 2 {
		t.Fatalf("Parameters len = %d, want 2", len(comp.Parameters))
	}
	if comp.Parameters[0].Type != "text" || comp.Parameters[0].Text != "one" {
		t.Errorf("Parameters[0] = %+v, want {text, one}", comp.Parameters[0])
	}
}

func TestNotify_PostsWithAuthHeader(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotCT     string
		gotBody   message
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"messages":[{"id":"wamid.TEST"}]}`))
	}))
	defer srv.Close()

	cfg := enabledConfig()
	cfg.BaseURL = srv.URL
	cfg.APIVersion = "v20.0"
	c := New(cfg, srv.Client())

	if err := c.Notify(context.Background(), "queries blocked spike detected"); err != nil {
		t.Fatalf("Notify() error = %v, want nil", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "/v20.0/1234567890/messages"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if want := "Bearer test-token"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody.To != "919999999999" || gotBody.Type != "text" {
		t.Errorf("body = %+v, want To=919999999999 Type=text", gotBody)
	}
	if gotBody.Text == nil || gotBody.Text.Body != "queries blocked spike detected" {
		t.Errorf("body.Text = %+v, want the sent message", gotBody.Text)
	}
}

func TestNotifyTemplate_PostsTemplatePayload(t *testing.T) {
	var gotBody message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := enabledConfig()
	cfg.BaseURL = srv.URL
	c := New(cfg, srv.Client())

	if err := c.NotifyTemplate(context.Background(), "daily_report", "en_US", "42"); err != nil {
		t.Fatalf("NotifyTemplate() error = %v, want nil", err)
	}
	if gotBody.Type != "template" || gotBody.Template == nil {
		t.Fatalf("body = %+v, want a template message", gotBody)
	}
	if gotBody.Template.Name != "daily_report" {
		t.Errorf("Template.Name = %q, want daily_report", gotBody.Template.Name)
	}
	if len(gotBody.Template.Components) != 1 || len(gotBody.Template.Components[0].Parameters) != 1 {
		t.Fatalf("Components = %+v, want one body param", gotBody.Template.Components)
	}
}

func TestNotify_Disabled_NoOp(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// No credentials => disabled. Point BaseURL at the server to prove it is
	// never contacted.
	cfg := Config{BaseURL: srv.URL}
	c := New(cfg, srv.Client())

	if c.Enabled() {
		t.Fatalf("Enabled() = true, want false")
	}
	if err := c.Notify(context.Background(), "should not send"); err != nil {
		t.Errorf("Notify() error = %v, want nil (no-op)", err)
	}
	if err := c.NotifyTemplate(context.Background(), "tpl", "en_US"); err != nil {
		t.Errorf("NotifyTemplate() error = %v, want nil (no-op)", err)
	}
	if called {
		t.Errorf("server was contacted, want no I/O when disabled")
	}
}

func TestNotify_EmptyMessage(t *testing.T) {
	c := New(enabledConfig(), nil)
	err := c.Notify(context.Background(), "   ")
	if err == nil || !strings.Contains(err.Error(), "empty message") {
		t.Errorf("Notify(empty) error = %v, want empty message error", err)
	}
}

func TestNotifyTemplate_EmptyName(t *testing.T) {
	c := New(enabledConfig(), nil)
	err := c.NotifyTemplate(context.Background(), "  ", "en_US")
	if err == nil || !strings.Contains(err.Error(), "empty template name") {
		t.Errorf("NotifyTemplate(empty) error = %v, want empty template name error", err)
	}
}

func TestNotify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid token"}}`))
	}))
	defer srv.Close()

	cfg := enabledConfig()
	cfg.BaseURL = srv.URL
	c := New(cfg, srv.Client())

	err := c.Notify(context.Background(), "hello")
	if err == nil {
		t.Fatalf("Notify() error = nil, want non-nil on 401")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("error = %v, want it to mention status 401 and body", err)
	}
}

func TestNotify_TransportError(t *testing.T) {
	// Server is closed immediately so the request fails at the transport layer.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client := srv.Client()
	srv.Close()

	cfg := enabledConfig()
	cfg.BaseURL = srv.URL
	c := New(cfg, client)

	err := c.Notify(context.Background(), "hello")
	if err == nil || !strings.Contains(err.Error(), "send request") {
		t.Errorf("Notify() error = %v, want a send request error", err)
	}
}
