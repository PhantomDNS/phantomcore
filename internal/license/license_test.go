// SPDX-License-Identifier: GPL-3.0-or-later
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// fixedNow returns a deterministic clock for tests.
func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// newTestClaims builds a claims value with the given expiry offset from base.
func newTestClaims(base time.Time, expiryOffset time.Duration) Claims {
	return Claims{
		Customer: "acme-schools",
		Tier:     "managed-pro",
		Issued:   base,
		Expiry:   base.Add(expiryOffset),
	}
}

func TestVerify_ValidToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	claims := newTestClaims(base, 30*24*time.Hour)

	token, err := Sign(claims, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("Verify returned error for valid token: %v", err)
	}
	if got.Customer != claims.Customer || got.Tier != claims.Tier {
		t.Errorf("claims mismatch: got %+v want %+v", got, claims)
	}
	if !got.Expiry.Equal(claims.Expiry) {
		t.Errorf("expiry mismatch: got %v want %v", got.Expiry, claims.Expiry)
	}
}

func TestVerify_TamperedPayloadRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, err := Sign(newTestClaims(base, 30*24*time.Hour), priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tamper with the payload: decode, mutate tier to a higher one, re-encode.
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected token shape: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	tampered := strings.Replace(string(payload), "managed-pro", "managed-xxl", 1)
	if tampered == string(payload) {
		t.Fatalf("tamper had no effect")
	}
	tamperedToken := base64.RawURLEncoding.EncodeToString([]byte(tampered)) + "." + parts[1]

	if _, err := Verify(tamperedToken, pub); err == nil {
		t.Fatal("Verify accepted a tampered token")
	}
}

func TestVerify_WrongKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, err := Sign(newTestClaims(base, time.Hour), priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Verify(token, otherPub); err == nil {
		t.Fatal("Verify accepted a token signed by a different key")
	}
}

func TestVerify_MalformedRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	for _, tok := range []string{"", "no-dot", "a.b.c", ".", "notbase64!.sig"} {
		if _, err := Verify(tok, pub); err == nil {
			t.Errorf("Verify accepted malformed token %q", tok)
		}
	}
}

func TestVerify_InvalidPublicKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	token, _ := Sign(newTestClaims(time.Now(), time.Hour), priv)
	if _, err := Verify(token, ed25519.PublicKey([]byte("short"))); err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestEvaluate_ModesAndGrace(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := base.Add(24 * time.Hour)
	claims := Claims{Customer: "acme", Tier: "managed-pro", Issued: base, Expiry: expiry}
	grace := 48 * time.Hour

	tests := []struct {
		name      string
		now       time.Time
		wantValid bool
		wantMode  Mode
		wantTier  string
	}{
		{"before expiry", expiry.Add(-time.Hour), true, ModeLicensed, "managed-pro"},
		{"at expiry", expiry, true, ModeLicensed, "managed-pro"},
		{"within grace", expiry.Add(24 * time.Hour), true, ModeGrace, "managed-pro"},
		{"just past grace", expiry.Add(grace + time.Second), false, ModeCommunity, CommunityTier},
		{"long past grace", expiry.Add(365 * 24 * time.Hour), false, ModeCommunity, CommunityTier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Evaluate(claims, tt.now, grace)
			if s.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", s.Valid, tt.wantValid)
			}
			if s.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", s.Mode, tt.wantMode)
			}
			if s.Tier != tt.wantTier {
				t.Errorf("Tier = %q, want %q", s.Tier, tt.wantTier)
			}
		})
	}
}

func TestLoad_ValidTokenLicensed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, _ := Sign(newTestClaims(base, 30*24*time.Hour), priv)

	l := Load(Options{
		Token:     token,
		PublicKey: pub,
		Now:       fixedNow(base.Add(time.Hour)),
	})
	s := l.Status()
	if !s.Valid || s.Mode != ModeLicensed {
		t.Fatalf("expected licensed+valid, got %+v", s)
	}
	if s.Tier != "managed-pro" || s.Customer != "acme-schools" {
		t.Errorf("unexpected claims in status: %+v", s)
	}
}

func TestLoad_ExpiredPastGraceIsCommunity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Expired 1 year ago, well past the default grace window.
	token, _ := Sign(newTestClaims(base, -365*24*time.Hour), priv)

	l := Load(Options{
		Token:     token,
		PublicKey: pub,
		Now:       fixedNow(base),
	})
	s := l.Status()
	if s.Valid || s.Mode != ModeCommunity {
		t.Fatalf("expected community+invalid for expired-past-grace, got %+v", s)
	}
	if s.Tier != CommunityTier {
		t.Errorf("expected community tier, got %q", s.Tier)
	}
}

func TestLoad_MissingTokenIsCommunity(t *testing.T) {
	l := Load(Options{}) // no token, no file
	s := l.Status()
	if s.Valid || s.Mode != ModeCommunity {
		t.Fatalf("expected community mode with no license, got %+v", s)
	}
	if s.Tier != CommunityTier {
		t.Errorf("expected community tier, got %q", s.Tier)
	}
}

func TestLoad_TamperedTokenFallsBackToCommunity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, _ := Sign(newTestClaims(base, 30*24*time.Hour), priv)
	// Corrupt the signature segment.
	tampered := token[:len(token)-2] + "AA"

	l := Load(Options{Token: tampered, PublicKey: pub, Now: fixedNow(base)})
	s := l.Status()
	if s.Valid || s.Mode != ModeCommunity {
		t.Fatalf("expected community fallback for tampered token, got %+v", s)
	}
}

func TestLoad_FromFile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, _ := Sign(newTestClaims(base, 30*24*time.Hour), priv)

	dir := t.TempDir()
	path := dir + "/license.key"
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write license file: %v", err)
	}
	l := Load(Options{File: path, PublicKey: pub, Now: fixedNow(base.Add(time.Hour))})
	if s := l.Status(); !s.Valid || s.Mode != ModeLicensed {
		t.Fatalf("expected licensed from file, got %+v", s)
	}
}

func TestLoad_MissingFileIsCommunity(t *testing.T) {
	l := Load(Options{File: "/nonexistent/does-not-exist.key"})
	if s := l.Status(); s.Valid || s.Mode != ModeCommunity {
		t.Fatalf("expected community mode for missing file, got %+v", s)
	}
}

func TestEmbeddedPublicKeyValid(t *testing.T) {
	pk := embeddedPublicKey()
	if len(pk) != ed25519.PublicKeySize {
		t.Fatalf("embedded public key has wrong size: %d", len(pk))
	}
}

func TestPackageDefaultStatus(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, _ := Sign(newTestClaims(base, 30*24*time.Hour), priv)

	Init(Options{Token: token, PublicKey: pub, Now: fixedNow(base.Add(time.Hour))})
	t.Cleanup(func() { Init(Options{}) }) // reset package default to community

	if s := Current(); !s.Valid || s.Mode != ModeLicensed {
		t.Fatalf("package Current() = %+v, want licensed", s)
	}
}
