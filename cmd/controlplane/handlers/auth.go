package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// GetAuthStatus returns whether initial setup has been completed.
func (h *APIHandler) GetAuthStatus(c *gin.Context) {
	setup, err := h.Store.Auth.IsSetup()
	if err != nil {
		log.Printf("auth status check failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   gin.H{"setup_complete": setup},
	})
}

type setupRequest struct {
	Password   string                  `json:"password" binding:"required,min=8"`
	Blocklists []setupBlocklistRequest `json:"blocklists,omitempty"`
}

type setupBlocklistRequest struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Format string `json:"format"`
}

// Setup creates the admin credential and optionally configures blocklists.
// Only works if setup has not been completed yet.
func (h *APIHandler) Setup(c *gin.Context) {
	setup, err := h.Store.Auth.IsSetup()
	if err != nil {
		log.Printf("setup check failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "internal error"})
		return
	}
	if setup {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "error": "setup already completed"})
		return
	}

	var req setupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "password is required (minimum 8 characters)"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "internal error"})
		return
	}

	apiKey := uuid.New().String()

	if err := h.Store.Auth.CreateAdmin(string(hash), apiKey); err != nil {
		log.Printf("admin creation failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "failed to create admin"})
		return
	}

	// Create blocklist sources if provided
	var warnings []string
	for _, bl := range req.Blocklists {
		// Validate URL scheme to prevent SSRF
		if !strings.HasPrefix(bl.URL, "http://") && !strings.HasPrefix(bl.URL, "https://") {
			warnings = append(warnings, "skipped "+bl.Name+": URL must use http:// or https://")
			continue
		}
		if bl.Format == "" {
			bl.Format = "hosts"
		}
		src := &models.BlocklistSource{
			ID:      bl.ID,
			Name:    bl.Name,
			URL:     bl.URL,
			Format:  bl.Format,
			Enabled: true,
		}
		if err := h.Store.Blocklist.CreateSource(src); err != nil {
			log.Printf("blocklist source creation failed for %s: %v", bl.ID, err)
			warnings = append(warnings, "failed to add "+bl.Name)
		}
	}

	resp := gin.H{"token": apiKey}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   resp,
	})
}

type loginRequest struct {
	Password string `json:"password" binding:"required"`
}

// Login validates the admin password and returns the API key.
//
// Brute-force protection: failed attempts from a client IP are tracked by
// h.loginRateLimiter(); after loginMaxAttempts failures within
// loginLockoutWindow, further attempts from that IP are rejected with 429
// until the window elapses. A successful login clears the IP's history.
func (h *APIHandler) Login(c *gin.Context) {
	ip := c.ClientIP()
	limiter := h.loginRateLimiter()
	if !limiter.allowed(ip) {
		c.JSON(http.StatusTooManyRequests, gin.H{"status": "error", "error": "too many failed login attempts — try again later"})
		return
	}

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "password is required"})
		return
	}

	admin, err := h.Store.Auth.GetAdmin()
	if err != nil {
		limiter.recordFailure(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)); err != nil {
		limiter.recordFailure(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "error": "invalid credentials"})
		return
	}

	limiter.recordSuccess(ip)
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   gin.H{"token": admin.APIKey},
	})
}
