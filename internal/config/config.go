package config

// SPDX-License-Identifier: GPL-3.0-or-later
import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lopster568/phantomDNS/internal/logger"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DataPlane    DataPlaneConfig    `yaml:"dataplane"`
	ControlPlane ControlPlaneConfig `yaml:"controlplane"`

	// LocalOnly is the data-custody master switch. When true, every
	// non-resolution outbound ("phone-home") network call MUST be
	// short-circuited. Default false.
	//
	// Do NOT read this field directly from outbound code paths; consult the
	// LocalOnly() accessor (env override aware) and AssertLocalOnlyRespected()
	// guard instead. See internal/config/local_only.go for the full contract.
	LocalOnly bool `yaml:"local_only"`
}

type GRPCServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Port       int    `yaml:"port"`
}

type DataPlaneConfig struct {
	ListenAddr              string           `yaml:"listen_addr"`
	UpstreamResolvers       []string         `yaml:"upstream_resolvers"`
	GRPCServer              GRPCServerConfig `yaml:"grpc_server"`
	BlocklistUpdateInterval string           `yaml:"blocklist_update_interval"`
	MetricsAddr             string           `yaml:"metrics_addr"`

	// BlocklistHealthInterval controls how often blocklist source health is
	// checked. Empty (zero value) uses the package default (1h).
	BlocklistHealthInterval string `yaml:"blocklist_health_interval"`

	// ThreatBlockThreshold enables enforcement of the heuristic threat detector.
	// When > 0, a query scored suspicious with ThreatScore >= threshold is blocked
	// (or logged as a would-be block when ThreatBlockDryRun is set). 0 disables
	// enforcement, preserving the historical log-only behaviour.
	ThreatBlockThreshold float64 `yaml:"threat_block_threshold"`
	// ThreatBlockDryRun logs would-be threat blocks without actually blocking.
	ThreatBlockDryRun bool `yaml:"threat_block_dryrun"`

	// AbusedTLDs is the set of high-abuse TLDs (e.g. "zip", "mov", "top") to
	// block on the default allow path. Empty (the default) disables the feature.
	AbusedTLDs []string `yaml:"abused_tlds"`

	// RebindProtection rejects upstream answers that map a public name to a
	// private/loopback/link-local IP (DNS rebinding defense). Default false.
	RebindProtection bool `yaml:"rebind_protection"`

	// ClientRateLimitPerSec caps DNS queries accepted per client IP each second.
	// 0 (the default) disables rate limiting entirely.
	ClientRateLimitPerSec int `yaml:"client_rate_limit_per_sec"`

	// SafeSearch, when true, rewrites well-known search/video hosts to their
	// enforced-safe CNAME targets (Google/Bing/DuckDuckGo SafeSearch and
	// YouTube Restricted Mode). Default false = no rewrite.
	SafeSearch bool `yaml:"safe_search"`

	// DNS0x20 enables DNS 0x20 case-randomization on outbound upstream queries
	// (anti-spoofing hardening). Default false = behaviour unchanged.
	DNS0x20 bool `yaml:"dns_0x20"`

	// WatchdogInterval is the self-heal watchdog probe cadence as a Go duration
	// (e.g. "30s"). Empty, "0" or "off" disables the watchdog.
	WatchdogInterval string `yaml:"watchdog_interval"`
	// WatchdogFailureThreshold is the number of consecutive unhealthy probes
	// before the watchdog attempts recovery. <= 0 uses the watchdog default.
	WatchdogFailureThreshold int `yaml:"watchdog_failure_threshold"`

	// ServeStale, when true, answers from an expired cache entry if the upstream
	// fails, so a transient upstream/ISP blip does not take DNS down. Default off.
	ServeStale bool `yaml:"serve_stale"`

	// Newly-observed-domain (NOD) detection. NODWindowHours is the first-seen
	// window in hours; 0 (the default) disables NOD entirely. When enabled, a
	// domain first seen on this resolver within the window is treated as newly
	// observed. NODBlock decides the action: false (default) flags and forwards,
	// true blocks the query. See internal/dnsengine/nod.go for the ledger.
	NODWindowHours int  `yaml:"nod_window_hours"`
	NODBlock       bool `yaml:"nod_block"`

	// FastFluxDetection enables the flag-only fast-flux heuristic (never blocks).
	// Disabled by default to avoid false positives on CDNs.
	FastFluxDetection bool `yaml:"fast_flux_detection"`
	// FastFluxIPThreshold is the number of distinct answer IPs within the sliding
	// window at or above which a low-TTL domain is flagged (default 8).
	FastFluxIPThreshold int `yaml:"fast_flux_ip_threshold"`
	// FastFluxTTLMaxSec is the maximum TTL (seconds) still considered "low" for
	// fast-flux flagging (default 300).
	FastFluxTTLMaxSec int `yaml:"fast_flux_ttl_max_sec"`

	// Event export targets. Both default empty = export disabled (OFF).
	// SyslogAddr accepts "udp://host:514" or "tcp://host:514".
	SyslogAddr      string `yaml:"syslog_addr"`
	EventWebhookURL string `yaml:"event_webhook_url"`

	// TyposquatBrands is the protected-brand watchlist for typosquat/homoglyph
	// detection (registrable domains, e.g. "paypal.com"). Empty => feature OFF.
	TyposquatBrands []string `yaml:"typosquat_brands"`
	// TyposquatBlock blocks typosquat hits instead of only flagging them.
	TyposquatBlock bool `yaml:"typosquat_block"`

	// Heartbeat is opt-in, metadata-only fleet status reporting. It is disabled
	// when HeartbeatURL is empty.
	HeartbeatURL      string `yaml:"heartbeat_url"`
	HeartbeatInterval string `yaml:"heartbeat_interval"`

	GeoIP GeoIPConfig `yaml:"geoip"`
}

// GeoIPConfig configures optional ASN/GeoIP answer filtering. It is disabled
// unless DBPath points at a MaxMind-format database (default: OFF, inert).
type GeoIPConfig struct {
	DBPath           string   `yaml:"db_path"`
	BlockedASNs      []uint   `yaml:"blocked_asns"`
	BlockedCountries []string `yaml:"blocked_countries"`
	// Block controls the enforcement mode on a match: false flags the answer as
	// suspicious but still returns it (default, safer for CDNs); true blocks it.
	Block bool `yaml:"block"`
}

// WatchdogIntervalDuration parses WatchdogInterval into a duration. It returns 0
// (watchdog disabled) when the value is empty, "0", "off", or unparseable.
func (c DataPlaneConfig) WatchdogIntervalDuration() time.Duration {
	s := strings.TrimSpace(c.WatchdogInterval)
	if s == "" || s == "0" || strings.EqualFold(s, "off") {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		logger.Log.Warnf("Invalid WATCHDOG_INTERVAL %q, disabling watchdog", c.WatchdogInterval)
		return 0
	}
	return d
}

type ControlPlaneConfig struct {
	ListenAddr string    `yaml:"listen_addr"`
	TLS        TLSConfig `yaml:"tls"`
}

// TLSConfig controls how the control-plane HTTP API is served.
//
// Selection precedence (see Mode):
//  1. CertFile+KeyFile both set  -> serve HTTPS with the operator-provided cert.
//  2. AutoSelfSigned true        -> generate/persist a self-signed cert, serve HTTPS.
//  3. otherwise                  -> plain HTTP (the default, no regression).
//
// Public ACME cannot issue certificates for private-LAN names, hence the
// operator-provided and self-signed options instead of automatic ACME.
type TLSConfig struct {
	// CertFile / KeyFile point to an operator-provided certificate and private
	// key (PEM). When both are set, TLS is served using them.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// AutoSelfSigned generates a self-signed certificate on first boot when no
	// cert/key pair is provided.
	AutoSelfSigned bool `yaml:"auto_self_signed"`
	// SelfSignedDir is where the generated self-signed cert/key are persisted so
	// they survive restarts.
	SelfSignedDir string `yaml:"self_signed_dir"`
}

// TLSMode is the resolved serving mode for the control-plane HTTP API.
type TLSMode int

const (
	// TLSModeDisabled serves plain HTTP (the default).
	TLSModeDisabled TLSMode = iota
	// TLSModeProvided serves HTTPS using an operator-provided cert/key.
	TLSModeProvided
	// TLSModeSelfSigned serves HTTPS using a generated, persisted self-signed cert.
	TLSModeSelfSigned
)

func (m TLSMode) String() string {
	switch m {
	case TLSModeProvided:
		return "provided"
	case TLSModeSelfSigned:
		return "self-signed"
	default:
		return "disabled"
	}
}

// Mode resolves how TLS should be served. A fully provided cert/key pair always
// wins; a partial pair (only one of the two) is ignored and falls through to the
// self-signed or disabled path so a misconfiguration never silently breaks boot.
func (t TLSConfig) Mode() TLSMode {
	if t.CertFile != "" && t.KeyFile != "" {
		return TLSModeProvided
	}
	if t.AutoSelfSigned {
		return TLSModeSelfSigned
	}
	return TLSModeDisabled
}

// Enabled reports whether the control-plane API should be served over TLS.
func (t TLSConfig) Enabled() bool {
	return t.Mode() != TLSModeDisabled
}

// DefaultSelfSignedDir is used when AutoSelfSigned is enabled but no directory
// was configured.
const DefaultSelfSignedDir = "/app/data/tls"

func defaultConfig() *Config {
	return &Config{
		DataPlane: DataPlaneConfig{
			ListenAddr:               "0.0.0.0:1053",
			UpstreamResolvers:        []string{"8.8.8.8:53", "1.1.1.1:53"},
			BlocklistUpdateInterval:  "6h",
			MetricsAddr:              "0.0.0.0:9153",
			BlocklistHealthInterval:  "1h",
			WatchdogInterval:         "30s",
			WatchdogFailureThreshold: 3,
			FastFluxDetection:        false,
			FastFluxIPThreshold:      8,
			FastFluxTTLMaxSec:        300,
			GRPCServer: GRPCServerConfig{
				Port:       50051,
				ListenAddr: "localhost:50051",
			},
		},
		ControlPlane: ControlPlaneConfig{
			ListenAddr: "0.0.0.0:8080",
			TLS: TLSConfig{
				SelfSignedDir: DefaultSelfSignedDir,
			},
		},
	}
}

func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Log.Warnf("Config file not found (%s), using defaults", path)
		return defaultConfig()
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		logger.Log.Errorf("Failed to unmarshal config: %v, using defaults", err)
		return defaultConfig()
	}

	return &cfg
}

var DefaultConfig = func() *Config {
	cfg := loadConfig(configPath())
	if addr := os.Getenv("DNS_LISTEN_ADDR"); addr != "" {
		cfg.DataPlane.ListenAddr = addr
	}
	if interval := os.Getenv("BLOCKLIST_UPDATE_INTERVAL"); interval != "" {
		cfg.DataPlane.BlocklistUpdateInterval = interval
	}
	if interval := os.Getenv("BLOCKLIST_HEALTH_INTERVAL"); interval != "" {
		cfg.DataPlane.BlocklistHealthInterval = interval
	}
	if v := os.Getenv("THREAT_BLOCK_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.DataPlane.ThreatBlockThreshold = f
		} else {
			logger.Log.Warnf("Invalid THREAT_BLOCK_THRESHOLD %q, ignoring: %v", v, err)
		}
	}
	if v := os.Getenv("THREAT_BLOCK_DRYRUN"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.ThreatBlockDryRun = b
		} else {
			logger.Log.Warnf("Invalid THREAT_BLOCK_DRYRUN %q, ignoring: %v", v, err)
		}
	}
	if v := os.Getenv("ABUSED_TLDS"); v != "" {
		cfg.DataPlane.AbusedTLDs = parseAbusedTLDs(v)
	}
	if v := os.Getenv("REBIND_PROTECTION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.RebindProtection = b
		} else {
			logger.Log.Warnf("Invalid REBIND_PROTECTION value %q: %v", v, err)
		}
	}
	if v := os.Getenv("CLIENT_RATE_LIMIT_PER_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.DataPlane.ClientRateLimitPerSec = n
		} else {
			logger.Log.Warnf("Invalid CLIENT_RATE_LIMIT_PER_SEC=%q, ignoring: %v", v, err)
		}
	}
	if v := os.Getenv("SAFE_SEARCH"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.SafeSearch = b
		}
	}
	if v := os.Getenv("DNS_0X20"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.DNS0x20 = b
		} else {
			logger.Log.Warnf("Invalid DNS_0X20 value %q, ignoring", v)
		}
	}
	if addr := os.Getenv("METRICS_LISTEN_ADDR"); addr != "" {
		cfg.DataPlane.MetricsAddr = addr
	}
	// Fall back to a sane default when a config file omits metrics_addr.
	if cfg.DataPlane.MetricsAddr == "" {
		cfg.DataPlane.MetricsAddr = "0.0.0.0:9153"
	}
	applyTLSEnv(&cfg.ControlPlane.TLS)
	if v := os.Getenv("WATCHDOG_INTERVAL"); v != "" {
		cfg.DataPlane.WatchdogInterval = v
	}
	if v := os.Getenv("WATCHDOG_FAILURE_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.DataPlane.WatchdogFailureThreshold = n
		} else {
			logger.Log.Warnf("Invalid WATCHDOG_FAILURE_THRESHOLD %q, using default", v)
		}
	}
	if v := os.Getenv("SERVE_STALE"); v == "true" || v == "1" {
		cfg.DataPlane.ServeStale = true
	}
	if v := os.Getenv("NOD_WINDOW_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.DataPlane.NODWindowHours = n
		} else {
			logger.Log.Warnf("Invalid NOD_WINDOW_HOURS=%q, ignoring: %v", v, err)
		}
	}
	if v := os.Getenv("NOD_BLOCK"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.NODBlock = b
		} else {
			logger.Log.Warnf("Invalid NOD_BLOCK=%q, ignoring: %v", v, err)
		}
	}
	if v := os.Getenv("FAST_FLUX_DETECTION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.FastFluxDetection = b
		}
	}
	if addr := os.Getenv("SYSLOG_ADDR"); addr != "" {
		cfg.DataPlane.SyslogAddr = addr
	}
	if webhook := os.Getenv("EVENT_WEBHOOK_URL"); webhook != "" {
		cfg.DataPlane.EventWebhookURL = webhook
	}
	if brands := os.Getenv("TYPOSQUAT_BRANDS"); brands != "" {
		cfg.DataPlane.TyposquatBrands = splitAndTrim(brands)
	}
	if block := os.Getenv("TYPOSQUAT_BLOCK"); block != "" {
		switch strings.ToLower(strings.TrimSpace(block)) {
		case "1", "true", "yes", "on":
			cfg.DataPlane.TyposquatBlock = true
		}
	}
	if url := os.Getenv("HEARTBEAT_URL"); url != "" {
		cfg.DataPlane.HeartbeatURL = url
	}
	if interval := os.Getenv("HEARTBEAT_INTERVAL"); interval != "" {
		cfg.DataPlane.HeartbeatInterval = interval
	}
	if p := os.Getenv("GEOIP_DB_PATH"); p != "" {
		cfg.DataPlane.GeoIP.DBPath = p
	}
	if v := os.Getenv("BLOCKED_ASNS"); v != "" {
		cfg.DataPlane.GeoIP.BlockedASNs = parseUintList(v)
	}
	if v := os.Getenv("BLOCKED_COUNTRIES"); v != "" {
		cfg.DataPlane.GeoIP.BlockedCountries = parseStringList(v)
	}
	if v := os.Getenv("GEOIP_BLOCK"); v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			cfg.DataPlane.GeoIP.Block = b
		}
	}
	return cfg
}()

// parseAbusedTLDs splits a comma-separated env value into a normalized list of
// TLDs: split on ",", trim surrounding spaces, lowercase, and drop empties.
func parseAbusedTLDs(v string) []string {
	parts := strings.Split(v, ",")
	tlds := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			tlds = append(tlds, p)
		}
	}
	return tlds
}

// applyTLSEnv overlays TLS_* environment variables onto the control-plane TLS
// config and fills in the self-signed directory default when unset.
func applyTLSEnv(t *TLSConfig) {
	if v := os.Getenv("TLS_CERT_FILE"); v != "" {
		t.CertFile = v
	}
	if v := os.Getenv("TLS_KEY_FILE"); v != "" {
		t.KeyFile = v
	}
	if v := os.Getenv("TLS_AUTO_SELF_SIGNED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			t.AutoSelfSigned = b
		} else {
			logger.Log.Warnf("invalid TLS_AUTO_SELF_SIGNED value %q, ignoring", v)
		}
	}
	if v := os.Getenv("TLS_SELF_SIGNED_DIR"); v != "" {
		t.SelfSignedDir = v
	}
	if t.SelfSignedDir == "" {
		t.SelfSignedDir = DefaultSelfSignedDir
	}
}

// splitAndTrim splits a comma-separated list, trimming whitespace and dropping
// empty entries.
func splitAndTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseUintList parses a comma-separated list of unsigned integers, skipping
// blank or malformed entries.
func parseUintList(s string) []uint {
	var out []uint
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, err := strconv.ParseUint(part, 10, 64); err == nil {
			out = append(out, uint(n))
		}
	}
	return out
}

// parseStringList parses a comma-separated list, trimming and dropping blanks.
func parseStringList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func configPath() string {
	if p := os.Getenv("PHANTOM_CONFIG"); p != "" {
		return p
	}
	return "/app/configs/config.yaml"
}

// BundledBlocklistEnabled reports whether the embedded offline blocklist should
// seed the DB on first boot. It is ON by default and can be disabled by setting
// BUNDLED_BLOCKLIST to a falsey value (e.g. "false", "0"). An unset or
// unparseable value keeps the default-on behaviour.
func BundledBlocklistEnabled() bool {
	v := os.Getenv("BUNDLED_BLOCKLIST")
	if v == "" {
		return true
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		logger.Log.Warnf("invalid BUNDLED_BLOCKLIST value %q; defaulting to enabled", v)
		return true
	}
	return enabled
}
