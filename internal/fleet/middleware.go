// SPDX-License-Identifier: GPL-3.0-or-later

package fleet

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const bearerPrefix = "Bearer "

// RequireHeartbeatToken guards the heartbeat endpoint. Boxes authenticate with
// a dedicated fleet token (Authorization: Bearer <token>) rather than the admin
// API key, so appliance credentials stay separate from operator credentials.
//
// An empty token means the feature is not usable, so requests are refused.
func RequireHeartbeatToken(token string) gin.HandlerFunc {
	want := []byte(token)
	return func(c *gin.Context) {
		if len(want) == 0 {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"status": "error",
				"error":  "fleet heartbeat disabled — no token configured",
			})
			return
		}

		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, bearerPrefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, bearerPrefix)), want) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"status": "error",
				"error":  "unauthorized — provide Authorization: Bearer <heartbeat-token>",
			})
			return
		}

		c.Next()
	}
}
