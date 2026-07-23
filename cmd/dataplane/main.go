package main

// SPDX-License-Identifier: GPL-3.0-or-later
import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lopster568/phantomDNS/internal/blocklist"
	"github.com/lopster568/phantomDNS/internal/blocklist/bundle"
	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/diskhealth"
	"github.com/lopster568/phantomDNS/internal/dnsengine"
	dataplanegrpc "github.com/lopster568/phantomDNS/internal/grpc/dataplane"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/metrics/promexport"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/db"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"github.com/lopster568/phantomDNS/internal/watchdog"
)

func main() {
	logger.Log.Info("Starting PhantomDNS Data Plane...")

	// 1. Initialize DB
	dbPath := "/app/data/phantomdns.db"
	if p := os.Getenv("PHANTOM_DB"); p != "" {
		dbPath = p
	}
	db.InitDB(dbPath)

	// 1b. Disk / SD-card health monitor (best-effort, non-fatal). Watches free
	// space and growth on the data path; expose diskMon.Status() from a
	// health / heartbeat surface. Configured via DISK_HEALTH_INTERVAL and
	// DISK_MIN_FREE_PERCENT.
	diskMon := diskhealth.NewMonitorFromEnv(dbPath)
	go diskMon.Run(context.Background())

	// 2. Initialize Repositories
	repos := repositories.NewStore(db.DB)

	// 3. Blocklist Engine — load from DB sources, refresh periodically
	blEngine := blocklist.NewEngine(repos.Blocklist)

	// Offline-first: seed the checker from the embedded bundle when the DB has
	// no blocklist snapshot yet, so the dataplane blocks well-known ad/malware
	// domains immediately on first boot with no internet. This runs before the
	// DNS server starts and only fires when nothing has ever been loaded; it
	// never overwrites data fetched by the online refresh below.
	if config.BundledBlocklistEnabled() {
		if seeded, err := bundle.SeedIfEmpty(repos.Blocklist); err != nil {
			logger.Log.Warnf("Bundled blocklist seed failed: %v", err)
		} else if seeded {
			logger.Log.Info("Seeded blocklist from embedded offline bundle (no snapshot present)")
		} else {
			logger.Log.Info("Bundled blocklist seed skipped (blocklist snapshot already present)")
		}
	} else {
		logger.Log.Info("Bundled blocklist seeding disabled via BUNDLED_BLOCKLIST")
	}

	// Initial load in background so DNS starts immediately
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		refreshBlocklists(ctx, blEngine, repos.Blocklist)
	}()

	// Periodic refresh
	interval, err := time.ParseDuration(config.DefaultConfig.DataPlane.BlocklistUpdateInterval)
	if err != nil || interval == 0 {
		interval = 6 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			refreshBlocklists(ctx, blEngine, repos.Blocklist)
			cancel()
		}
	}()

	// 3b. Blocklist source health monitoring — flags dead, collapsed, or stale
	// sources on an interval. Non-fatal; results are retained for status/heartbeat.
	healthChecker := blocklist.NewHealthChecker(repos.Blocklist, blocklist.DefaultHealthThresholds(), time.Now)
	go healthChecker.Run(context.Background(), healthInterval(config.DefaultConfig.DataPlane.BlocklistHealthInterval))

	// 4. Initialize Policy Engine — load from file + DB
	policyEngine := policy.NewPolicyEngine()
	policiesPath := "/app/configs/policies.json"
	if p := os.Getenv("PHANTOM_POLICIES"); p != "" {
		policiesPath = p
	}
	filePolicies, err := policy.LoadPoliciesFromFile(policiesPath)
	if err != nil {
		logger.Log.Warnf("failed to load policies from file: %v (continuing with DB policies only)", err)
		filePolicies = nil
	}

	// Merge file policies + DB policies
	reloadPolicies(policyEngine, filePolicies, repos.Policies)

	// Poll DB for policy changes every 5 seconds
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			reloadPolicies(policyEngine, filePolicies, repos.Policies)
		}
	}()

	// 5. Initialize DNS Engine
	engine, err := dnsengine.NewDNSEngine(config.DefaultConfig.DataPlane, repos, policyEngine)
	if err != nil {
		logger.Log.Fatal("Failed to create DNS engine: " + err.Error())
	}

	// 6. gRPC server
	statusService := dataplanegrpc.NewStatusService(engine)
	metricsService := dataplanegrpc.NewMetricsService(engine)
	grpcSrv := dataplanegrpc.New(config.DefaultConfig.DataPlane.GRPCServer.Port, statusService, metricsService)

	go func() {
		logger.Log.Info("Starting dataplane gRPC server on :50051")
		if err := grpcSrv.Start(); err != nil {
			logger.Log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	// 6b. Prometheus metrics HTTP server.
	// Metrics are in-process here (engine.Metrics()), so /metrics is exposed
	// directly on the dataplane rather than bridged over gRPC.
	go func() {
		metricsAddr := config.DefaultConfig.DataPlane.MetricsAddr
		mux := http.NewServeMux()
		mux.Handle("/metrics", promexport.Handler(engine.Metrics()))
		metricsSrv := &http.Server{
			Addr:              metricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		logger.Log.Infof("Starting dataplane metrics server on %s/metrics", metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.Errorf("metrics server failed: %v", err)
		}
	}()

	// 7. Attach blocklist checker and start DNS server
	engine.AttachBlocklistChecker(repos.Blocklist)
	srv, err := dnsengine.NewServer(config.DefaultConfig.DataPlane, engine)
	if err != nil {
		logger.Log.Fatal("Failed to create server: " + err.Error())
	}

	// 8. Self-heal watchdog — supervise dataplane liveness on unattended boxes.
	// Probe: the engine must be accepting queries. Recovery: an in-process
	// listener restart is not safely in scope from here (the DNS server owns its
	// own bind/shutdown lifecycle), so we emit a critical log line instead; the
	// systemd unit (deploy/hydradns.service, Restart=always) handles bare-metal
	// process-level recovery when the box is truly wedged.
	startWatchdog(engine)

	logger.Log.Infof("DNS server listening on %s", config.DefaultConfig.DataPlane.ListenAddr)
	srv.Run()
}

// healthInterval parses the configured blocklist health interval. "off", "0",
// "disabled", or an empty value turn the periodic monitor off (a single check
// still runs); an unparseable value falls back to 1h.
func healthInterval(v string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return time.Hour
	case "off", "0", "disabled":
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logger.Log.Warnf("invalid BLOCKLIST_HEALTH_INTERVAL %q, using 1h", v)
		return time.Hour
	}
	return d
}

// startWatchdog constructs and launches the self-heal watchdog for the DNS
// engine. It is a no-op when WATCHDOG_INTERVAL disables it. The watchdog is
// started in a background goroutine that first waits for the DNS server to come
// up, so the normal startup window is not flagged as unhealthy.
func startWatchdog(engine *dnsengine.Engine) {
	wd := watchdog.New(
		watchdog.Config{
			Interval:         config.DefaultConfig.DataPlane.WatchdogIntervalDuration(),
			FailureThreshold: config.DefaultConfig.DataPlane.WatchdogFailureThreshold,
		},
		// Liveness probe: engine is healthy while it is accepting queries.
		func() bool { return engine.Status().AcceptingQueries },
		// Recovery: log critically for external supervision. Restarting the DNS
		// listener in-process is not safely in scope here; deploy/hydradns.service
		// (Restart=always) provides bare-metal auto-restart for hard failures.
		func() {
			logger.Log.Error("watchdog: dataplane stalled (engine not accepting queries); " +
				"relying on systemd Restart=always for bare-metal recovery")
		},
		logger.Log,
	)

	if !wd.Enabled() {
		logger.Log.Info("Self-heal watchdog disabled (WATCHDOG_INTERVAL off)")
		return
	}

	go func() {
		// Wait for the server to start accepting queries before supervising.
		for !engine.Status().AcceptingQueries {
			time.Sleep(500 * time.Millisecond)
		}
		wd.Start(context.Background())
	}()
}

func refreshBlocklists(ctx context.Context, engine *blocklist.Engine, repo repositories.BlocklistRepository) {
	sources, err := repo.ListSources()
	if err != nil {
		logger.Log.Errorf("Failed to list blocklist sources: %v", err)
		return
	}
	if len(sources) == 0 {
		logger.Log.Info("No blocklist sources configured")
		return
	}
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		if err := engine.UpdateSource(ctx, src, src.ETag); err != nil {
			logger.Log.Errorf("Blocklist update failed for %s: %v", src.Name, err)
		}
	}
	count, _ := engine.List()
	logger.Log.Infof("Blocklist refresh complete: %d total domains blocked", len(count))
}

func reloadPolicies(engine *policy.Engine, filePolicies []policy.Policy, repo repositories.PolicyRepository) {
	// Start with file-based policies
	all := make([]policy.Policy, len(filePolicies))
	copy(all, filePolicies)

	// Add DB policies
	dbPolicies, err := repo.List()
	if err != nil {
		logger.Log.Errorf("Failed to load policies from DB: %v", err)
	} else {
		for _, dbp := range dbPolicies {
			all = append(all, dbPolicyToEngine(dbp))
		}
	}

	if err := engine.LoadPolicies(all); err != nil {
		logger.Log.Errorf("Failed to reload policy snapshot: %v", err)
	}
}

func dbPolicyToEngine(m models.Policy) policy.Policy {
	var domains []string
	if m.Domains != "" {
		_ = json.Unmarshal([]byte(m.Domains), &domains)
	}
	return policy.Policy{
		ID:       m.ID,
		Name:     m.Name,
		Action:   m.Action,
		Domains:  domains,
		Priority: m.Priority,
		Enabled:  m.Enabled,
		Category: m.Category,
		Redirect: m.RedirectIP,
	}
}
