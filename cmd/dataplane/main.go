package main

// SPDX-License-Identifier: GPL-3.0-or-later
import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/lopster568/phantomDNS/internal/blocklist"
	"github.com/lopster568/phantomDNS/internal/config"
	"github.com/lopster568/phantomDNS/internal/diskhealth"
	"github.com/lopster568/phantomDNS/internal/dnsengine"
	dataplanegrpc "github.com/lopster568/phantomDNS/internal/grpc/dataplane"
	"github.com/lopster568/phantomDNS/internal/logger"
	"github.com/lopster568/phantomDNS/internal/policy"
	"github.com/lopster568/phantomDNS/internal/storage/db"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
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

	// 7. Attach blocklist checker and start DNS server
	engine.AttachBlocklistChecker(repos.Blocklist)
	srv, err := dnsengine.NewServer(config.DefaultConfig.DataPlane, engine)
	if err != nil {
		logger.Log.Fatal("Failed to create server: " + err.Error())
	}

	logger.Log.Infof("DNS server listening on %s", config.DefaultConfig.DataPlane.ListenAddr)
	srv.Run()
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
