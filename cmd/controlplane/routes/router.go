package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/cmd/controlplane/handlers"
)

func RegisterRoutes(r *gin.Engine, apiHandler *handlers.APIHandler) {
	api := r.Group("/api/v1")
	r.GET("/health", apiHandler.HealthCheck)
	r.GET("/", apiHandler.Root)
	{
		// Auth endpoints (unprotected — middleware exempts these paths)
		auth := api.Group("/auth")
		{
			auth.GET("/status", apiHandler.GetAuthStatus)
			auth.POST("/setup", apiHandler.Setup)
			auth.POST("/login", apiHandler.Login)
		}

		// Dashboard endpoints
		dashboard := api.Group("/dashboard")
		{
			dashboard.GET("/summary", apiHandler.GetDashboardSummary)
		}

		// DNS Engine endpoints
		dns := api.Group("/dns")
		{
			dns.GET("/engine", apiHandler.GetDnsEngineStatus)
			dns.POST("/engine", apiHandler.ToggleDnsEngine)
			dns.GET("/resolvers", apiHandler.ListResolvers)
			dns.POST("/resolvers", apiHandler.CreateResolver)
			dns.PUT("/resolvers/:id", apiHandler.UpdateResolver)
			dns.PATCH("/resolvers/:id", apiHandler.UpdateResolver)
			dns.DELETE("/resolvers/:id", apiHandler.DeleteResolver)
			dns.GET("/metrics", apiHandler.GetDnsMetrics)
		}

		// Policies endpoints
		policies := api.Group("/policies")
		{
			policies.GET("", apiHandler.ListPolicies)
			policies.POST("", apiHandler.CreatePolicy)
			policies.GET("/:id", apiHandler.GetPolicy)
			policies.PUT("/:id", apiHandler.UpdatePolicy)
			policies.PATCH("/:id", apiHandler.UpdatePolicy)
			policies.DELETE("/:id", apiHandler.DeletePolicy)
		}

		// Blocklists endpoints
		blocklists := api.Group("/blocklists")
		{
			blocklists.GET("", apiHandler.ListBlocklists)
			blocklists.POST("", apiHandler.CreateBlocklist)
			blocklists.GET("/:id", apiHandler.GetBlocklist)
			blocklists.PUT("/:id", apiHandler.UpdateBlocklist)
			blocklists.PATCH("/:id", apiHandler.UpdateBlocklist)
			blocklists.DELETE("/:id", apiHandler.DeleteBlocklist)
		}

		// Category endpoints — curated feed catalog toggles (I-013/I-064/I-102/I-154)
		categories := api.Group("/categories")
		{
			categories.GET("", apiHandler.ListCategories)
			categories.GET("/:name", apiHandler.GetCategory)
			categories.PATCH("/:name", apiHandler.ToggleCategory)
			categories.PUT("/:name", apiHandler.ToggleCategory)
		}

		// Collection endpoints — per-app domain bundles (I-052)
		collections := api.Group("/collections")
		{
			collections.GET("", apiHandler.ListCollections)
			collections.PATCH("/:name", apiHandler.ToggleCollection)
			collections.PUT("/:name", apiHandler.ToggleCollection)
		}

		// Analytics endpoints
		analytics := api.Group("/analytics")
		{
			analytics.GET("/summary", apiHandler.GetAnalyticsSummary)
			analytics.GET("/audits", apiHandler.GetAuditLogs)
			analytics.GET("/logs", apiHandler.GetQueryLogs)
			analytics.GET("/rollups", apiHandler.GetAnalyticsRollups)
		}

		// Device inventory endpoints
		devices := api.Group("/devices")
		{
			devices.GET("", apiHandler.GetDevices)
		}

		// Config export/import endpoints
		cfg := api.Group("/config")
		{
			cfg.GET("/export", apiHandler.ExportConfig)
			cfg.POST("/import", apiHandler.ImportConfig)
		}

		// Reporting endpoint — plain-language period report (text/html/json)
		api.GET("/reports", apiHandler.GetReport)
	}
}
