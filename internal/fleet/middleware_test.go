// SPDX-License-Identifier: GPL-3.0-or-later

package fleet

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func newAuthEngine(token string) *gin.Engine {
	r := gin.New()
	r.POST("/hb", RequireHeartbeatToken(token), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "success"})
	})
	return r
}

func TestRequireHeartbeatToken(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		authHeader string
		wantStatus int
	}{
		{"valid token", "s3cret", "Bearer s3cret", http.StatusOK},
		{"missing header", "s3cret", "", http.StatusUnauthorized},
		{"wrong token", "s3cret", "Bearer nope", http.StatusUnauthorized},
		{"no bearer prefix", "s3cret", "s3cret", http.StatusUnauthorized},
		{"disabled (empty token)", "", "Bearer anything", http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newAuthEngine(tt.token)
			req := httptest.NewRequest(http.MethodPost, "/hb", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
