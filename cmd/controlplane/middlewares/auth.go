package middlewares

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
)

func Auth(authRepo repositories.AuthRepository) gin.HandlerFunc {
	// Paths that don't require authentication
	exemptPaths := map[string]bool{
		"/health":             true,
		"/":                   true,
		"/api/v1/auth/status": true,
		"/api/v1/auth/login":  true,
		"/api/v1/auth/setup":  true,
	}

	return func(c *gin.Context) {
		if exemptPaths[c.Request.URL.Path] {
			c.Next()
			return
		}

		// Check if setup is complete — if not, block all non-exempt routes
		setup, err := authRepo.IsSetup()
		if err != nil || !setup {
			c.AbortWithStatusJSON(403, gin.H{
				"status": "error",
				"error":  "setup required — complete setup at /api/v1/auth/setup",
			})
			return
		}

		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{
				"status": "error",
				"error":  "unauthorized — provide Authorization: Bearer <token>",
			})
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		valid, err := authRepo.ValidateAPIKey(token)
		if err != nil || !valid {
			c.AbortWithStatusJSON(401, gin.H{
				"status": "error",
				"error":  "invalid token",
			})
			return
		}

		c.Next()
	}
}
