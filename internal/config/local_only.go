// SPDX-License-Identifier: GPL-3.0-or-later
package config

import (
	"os"
	"strings"

	"github.com/lopster568/phantomDNS/internal/logger"
)

// ============================================================================
// LOCAL_ONLY — data-custody master switch (I-061)
// ============================================================================
//
// HydraDNS makes a provable data-custody guarantee: when LOCAL_ONLY is engaged,
// the appliance performs NO non-resolution outbound network traffic. Nothing
// "phones home" — no telemetry, no usage analytics, no update pings, no crash
// reports, no remote config pulls. Only the traffic required to actually
// resolve and filter DNS leaves the box.
//
// THE CONTRACT
// ------------
// Any code path that makes a NON-RESOLUTION outbound network request MUST call
// AssertLocalOnlyRespected (or check LocalOnly()) FIRST and skip / no-op the
// request when custody mode is engaged. This is a hard requirement, not a
// best-effort. New outbound features are reviewed against this contract.
//
// ALLOWED under LOCAL_ONLY (core resolution/filtering — NEVER gated):
//   - DNS resolution to configured upstream resolvers
//     (internal/dnsengine/*, e.g. connections.go net.Dial).
//   - Blocklist source fetch over HTTP(S)
//     (internal/blocklist/fetcher/http_client.go). This is a core filtering
//     function pulling operator-configured blocklists, not a phone-home.
//   - Intra-appliance gRPC between control plane and data plane
//     (internal/grpc/*), which stays on localhost.
//
// GATED under LOCAL_ONLY (non-resolution / phone-home — MUST no-op when true):
//   - Telemetry / usage analytics reporting (see internal/telemetry).
//   - Software update / version checks.
//   - Crash / error reporting to any remote sink.
//   - Remote managed-config or license/heartbeat calls.
//   - Any future feature that sends data off-box for a reason other than
//     resolving or filtering a DNS query.
//
// Some of the gated features live on other branches; the accessor, the guard,
// and this contract land on main so those branches have a single switch to
// consult. internal/telemetry ships the reference implementation of the guard
// pattern.

// LocalOnly reports whether the data-custody master switch is engaged.
//
// Precedence: the LOCAL_ONLY environment variable (if set to a recognized
// boolean) overrides the yaml/config value; otherwise the configured value is
// used. Default is false (normal operation).
//
// Outbound, non-resolution code paths MUST consult this (or
// AssertLocalOnlyRespected) and no-op when it returns true.
func LocalOnly() bool {
	if v, ok := envBool("LOCAL_ONLY"); ok {
		return v
	}
	return DefaultConfig.LocalOnly
}

// AssertLocalOnlyRespected is the guard that non-resolution outbound features
// MUST call before performing a phone-home request. It returns true when the
// caller MAY proceed with the outbound request, and false when LOCAL_ONLY
// custody mode requires the caller to skip / no-op it.
//
// The feature argument is a short identifier (e.g. "telemetry.Report") used
// only for logging when a call is suppressed.
//
// Canonical usage:
//
//	if !config.AssertLocalOnlyRespected("telemetry.Report") {
//	    return nil // custody mode: no-op, make no outbound request
//	}
//	// ... perform the outbound request ...
func AssertLocalOnlyRespected(feature string) (mayProceed bool) {
	if LocalOnly() {
		logger.Log.Warnf("LOCAL_ONLY custody mode engaged: suppressing outbound feature %q", feature)
		return false
	}
	return true
}

// LogCustodyMode emits a single startup log line stating the current custody
// mode. Call it once during process startup (data plane and control plane).
func LogCustodyMode() {
	if LocalOnly() {
		logger.Log.Info("data custody: LOCAL_ONLY mode ENGAGED — all non-resolution outbound (phone-home) calls are disabled")
	} else {
		logger.Log.Info("data custody: LOCAL_ONLY mode disabled — non-resolution outbound calls permitted (default)")
	}
}

// envBool reads a boolean-ish environment variable. ok is false when the
// variable is unset, empty, or not a recognized boolean (in which case the
// caller should fall back to the configured value).
func envBool(key string) (value bool, ok bool) {
	raw, present := os.LookupEnv(key)
	if !present {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}
