// SPDX-License-Identifier: GPL-3.0-or-later

// Package license implements soft validation of managed-service license
// tokens for HydraDNS.
//
// IMPORTANT (GPL-friendly design): this is a SOFT gate. It only unlocks
// premium/managed features and support. Core DNS resolution and filtering
// MUST always work regardless of license state. A missing, malformed, or
// expired-beyond-grace license simply downgrades the installation to
// "community" mode — the resolver is never affected.
//
// A license token is a signed payload of the form:
//
//	base64url(payloadJSON) "." base64url(ed25519Signature)
//
// where payloadJSON marshals the Claims struct (customer, tier, issued,
// expiry). The signature is produced with an Ed25519 private key held by
// HydraDNS and verified with the corresponding public key (embedded below,
// overridable via Options.PublicKey for testing/tooling).
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
)

// Mode describes the operational licensing mode of the installation.
type Mode string

const (
	// ModeCommunity means no valid license: premium/managed features are
	// locked. Core DNS resolution/filtering is unaffected.
	ModeCommunity Mode = "community"
	// ModeLicensed means a valid, unexpired license is present.
	ModeLicensed Mode = "licensed"
	// ModeGrace means the license expired but is still within the grace
	// window; premium features remain enabled while renewal is pending.
	ModeGrace Mode = "grace"
)

// CommunityTier is the tier reported when no valid license is present.
const CommunityTier = "community"

// DefaultGracePeriod is how long premium features keep working after a
// license expires, giving customers time to renew without disruption.
const DefaultGracePeriod = 14 * 24 * time.Hour

// embeddedPublicKeyB64 is the base64 (std encoding) Ed25519 public key used
// to verify license tokens.
//
// PLACEHOLDER: this key is a documented placeholder generated for the
// open-source build. Managed/enterprise builds replace it (or override it
// at load time via Options.PublicKey) with HydraDNS's real signing key.
// Because validation is a soft gate, shipping the placeholder is safe: it
// only means no production license verifies against it, so the build runs
// in community mode.
const embeddedPublicKeyB64 = "BwTPBVExuwQ9o/HrHbhg+ee/ldvORAf5hb6nctCR8F8="

// Errors returned by Verify.
var (
	// ErrMalformedToken indicates the token is not in the expected
	// "payload.signature" base64url form or the payload is not valid JSON.
	ErrMalformedToken = errors.New("license: malformed token")
	// ErrBadSignature indicates the signature did not verify against the
	// public key (tampered or forged token).
	ErrBadSignature = errors.New("license: signature verification failed")
	// ErrInvalidPublicKey indicates the verifier public key is missing or
	// the wrong size.
	ErrInvalidPublicKey = errors.New("license: invalid public key")
	// ErrIncompleteClaims indicates required claim fields are missing.
	ErrIncompleteClaims = errors.New("license: incomplete claims")
)

// Claims is the license payload carried by a token.
type Claims struct {
	Customer string    `json:"customer"`
	Tier     string    `json:"tier"`
	Issued   time.Time `json:"issued"`
	Expiry   time.Time `json:"expiry"`
}

// Status is a snapshot of the current licensing state. It is what callers
// (e.g. the control plane / UI) inspect to decide whether to expose premium
// features. It intentionally carries no capability to affect resolution.
type Status struct {
	// Valid is true when premium/managed features should be enabled
	// (licensed or within the grace window).
	Valid bool `json:"valid"`
	// Tier is the licensed tier, or CommunityTier when not licensed.
	Tier string `json:"tier"`
	// Customer is the licensed customer id, empty in community mode.
	Customer string `json:"customer,omitempty"`
	// Expiry is the license expiry, zero in community mode.
	Expiry time.Time `json:"expiry,omitempty"`
	// Mode is the operational mode: community, licensed, or grace.
	Mode Mode `json:"mode"`
}

// communityStatus returns the default, unlicensed status.
func communityStatus() Status {
	return Status{Valid: false, Tier: CommunityTier, Mode: ModeCommunity}
}

// Sign produces a license token for the given claims using an Ed25519
// private key. It is primarily used by license-issuing tooling and tests.
func Sign(c Claims, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("license: invalid private key size %d", len(priv))
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks a token's Ed25519 signature against pub and parses its
// claims. It validates the signature and structural integrity only; expiry
// and grace evaluation is done by Evaluate. A tampered payload or signature
// yields ErrBadSignature.
func Verify(token string, pub ed25519.PublicKey) (Claims, error) {
	var c Claims
	if len(pub) != ed25519.PublicKeySize {
		return c, ErrInvalidPublicKey
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return c, ErrMalformedToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, fmt.Errorf("%w: bad payload encoding: %v", ErrMalformedToken, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, fmt.Errorf("%w: bad signature encoding: %v", ErrMalformedToken, err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return c, ErrBadSignature
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("%w: %v", ErrMalformedToken, err)
	}
	if c.Customer == "" || c.Tier == "" {
		return c, ErrIncompleteClaims
	}
	return c, nil
}

// Evaluate turns verified claims into a Status given the current time and a
// grace window. If grace <= 0, DefaultGracePeriod is used.
//
//   - now <= expiry              -> licensed (valid)
//   - expiry < now <= expiry+grace -> grace   (valid)
//   - now > expiry+grace         -> community (invalid)
func Evaluate(c Claims, now time.Time, grace time.Duration) Status {
	if grace <= 0 {
		grace = DefaultGracePeriod
	}
	switch {
	case !now.After(c.Expiry):
		return Status{
			Valid:    true,
			Tier:     c.Tier,
			Customer: c.Customer,
			Expiry:   c.Expiry,
			Mode:     ModeLicensed,
		}
	case now.Before(c.Expiry.Add(grace)):
		return Status{
			Valid:    true,
			Tier:     c.Tier,
			Customer: c.Customer,
			Expiry:   c.Expiry,
			Mode:     ModeGrace,
		}
	default:
		return communityStatus()
	}
}

// embeddedPublicKey decodes the embedded placeholder public key. It returns
// nil if the constant is somehow invalid, in which case verification fails
// closed to community mode.
func embeddedPublicKey() ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(embeddedPublicKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}

// Options configures how a license is loaded and evaluated.
type Options struct {
	// Token is a raw license token (from the LICENSE_KEY env var / config).
	// Takes precedence over File.
	Token string
	// File is a path to a file containing a license token (LICENSE_FILE).
	File string
	// PublicKey overrides the embedded verifier key. Defaults to the
	// embedded placeholder key when nil.
	PublicKey ed25519.PublicKey
	// Grace overrides the grace window. Defaults to DefaultGracePeriod.
	Grace time.Duration
	// Now overrides the clock, for deterministic evaluation in tests.
	Now func() time.Time
}

// License holds the evaluated licensing state of the installation.
type License struct {
	status Status
	claims Claims
}

// Status returns the current licensing status snapshot.
func (l *License) Status() Status { return l.status }

// Claims returns the verified claims. In community mode the zero value is
// returned.
func (l *License) Claims() Claims { return l.claims }

// Load reads and evaluates a license from opts. It NEVER fails hard: any
// problem (missing token, unreadable file, bad signature, expiry beyond
// grace) results in a community-mode License. This is the core of the soft
// gate — license trouble must never break the running service.
func Load(opts Options) *License {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	pub := opts.PublicKey
	if pub == nil {
		pub = embeddedPublicKey()
	}

	token := strings.TrimSpace(opts.Token)
	if token == "" && opts.File != "" {
		data, err := os.ReadFile(opts.File)
		if err != nil {
			logger.Log.Warnf("license: cannot read LICENSE_FILE %q: %v; running in community mode", opts.File, err)
			return &License{status: communityStatus()}
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		// No license configured: this is the normal open-source path.
		return &License{status: communityStatus()}
	}

	claims, err := Verify(token, pub)
	if err != nil {
		logger.Log.Warnf("license: verification failed: %v; running in community mode", err)
		return &License{status: communityStatus()}
	}

	status := Evaluate(claims, now(), opts.Grace)
	switch status.Mode {
	case ModeGrace:
		logger.Log.Warnf("license: token for %q expired on %s; running in grace period, please renew",
			claims.Customer, claims.Expiry.Format(time.RFC3339))
	case ModeCommunity:
		logger.Log.Warnf("license: token for %q expired beyond grace on %s; running in community mode",
			claims.Customer, claims.Expiry.Format(time.RFC3339))
	}
	return &License{status: status, claims: claims}
}

// Package-level default license, so callers can query Status() without
// threading a *License everywhere. Defaults to community mode until Init.
var (
	mu  sync.RWMutex
	std = &License{status: communityStatus()}
)

// Init loads a license from opts and installs it as the package default.
func Init(opts Options) *License {
	l := Load(opts)
	mu.Lock()
	std = l
	mu.Unlock()
	return l
}

// InitFromEnv loads the package default license from the LICENSE_KEY and
// LICENSE_FILE environment variables. LICENSE_KEY takes precedence.
func InitFromEnv() *License {
	return Init(Options{
		Token: os.Getenv("LICENSE_KEY"),
		File:  os.Getenv("LICENSE_FILE"),
	})
}

// Current returns the current status of the package default license. It is
// the package-level counterpart to (*License).Status().
func Current() Status {
	mu.RLock()
	defer mu.RUnlock()
	return std.status
}
