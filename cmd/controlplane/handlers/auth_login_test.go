// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"github.com/lopster568/phantomDNS/internal/storage/repositories"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const testLoginPassword = "correct-horse-battery-staple"

// newLoginTestServer wires just the /login route over an in-memory DB with a
// real bcrypt-hashed admin password, and returns the handler so tests can
// reach into its rate limiter (e.g. to fast-forward its clock).
func newLoginTestServer(t *testing.T) (*gin.Engine, *APIHandler) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&models.AdminCredential{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(testLoginPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	store := repositories.NewStore(db)
	if err := store.Auth.CreateAdmin(string(hash), "admin-token-xyz"); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	h := NewAPIHandler(*store, nil, nil, nil, nil, "")

	r := gin.New()
	r.POST("/api/v1/auth/login", h.Login)
	return r, h
}

func loginReq(r *gin.Engine, remoteAddr, password string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(loginRequest{Password: password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestLogin_UnderLimit_PassesThrough(t *testing.T) {
	r, _ := newLoginTestServer(t)
	const ip = "203.0.113.1:5555"

	// A few wrong-password attempts, all under the limit, must each be
	// evaluated normally (401), not rate-limited (429).
	for i := 0; i < loginMaxAttempts-1; i++ {
		w := loginReq(r, ip, "wrong-password")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, w.Code)
		}
	}

	// The correct password should still succeed (limiter hasn't tripped).
	w := loginReq(r, ip, testLoginPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("final correct attempt: status = %d body=%s, want 200", w.Code, w.Body.String())
	}
}

func TestLogin_OverLimit_Returns429(t *testing.T) {
	r, _ := newLoginTestServer(t)
	const ip = "203.0.113.2:5555"

	for i := 0; i < loginMaxAttempts; i++ {
		w := loginReq(r, ip, "wrong-password")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, w.Code)
		}
	}

	// One more attempt, even with the correct password, must be rejected.
	w := loginReq(r, ip, testLoginPassword)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt over the limit: status = %d body=%s, want 429", w.Code, w.Body.String())
	}

	// A different IP is unaffected by this one's lockout.
	w = loginReq(r, "198.51.100.3:5555", testLoginPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("unrelated IP: status = %d body=%s, want 200", w.Code, w.Body.String())
	}
}

func TestLogin_WindowExpiry_Resets(t *testing.T) {
	r, h := newLoginTestServer(t)
	const ip = "203.0.113.3:5555"

	for i := 0; i < loginMaxAttempts; i++ {
		loginReq(r, ip, "wrong-password")
	}
	if w := loginReq(r, ip, testLoginPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected lockout after %d failures, got status %d", loginMaxAttempts, w.Code)
	}

	// Fast-forward the limiter's clock past the lockout window.
	limiter := h.loginRateLimiter()
	base := limiter.now()
	limiter.now = func() time.Time { return base.Add(loginLockoutWindow + time.Second) }

	if w := loginReq(r, ip, testLoginPassword); w.Code != http.StatusOK {
		t.Fatalf("expected login to succeed after the lockout window expired, got status %d body=%s", w.Code, w.Body.String())
	}
}

func TestLogin_Success_ResetsCounter(t *testing.T) {
	r, _ := newLoginTestServer(t)
	const ip = "203.0.113.4:5555"

	// A couple of failures, then a success.
	loginReq(r, ip, "wrong-password")
	loginReq(r, ip, "wrong-password")
	if w := loginReq(r, ip, testLoginPassword); w.Code != http.StatusOK {
		t.Fatalf("expected success, got status %d", w.Code)
	}

	// The counter should be back at zero: loginMaxAttempts more failures are
	// needed to trip the limiter again, not just the remainder from before.
	for i := 0; i < loginMaxAttempts; i++ {
		w := loginReq(r, ip, "wrong-password")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("post-success attempt %d: status = %d, want 401 (counter should have reset)", i+1, w.Code)
		}
	}
	if w := loginReq(r, ip, testLoginPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the limiter to trip again after a fresh %d failures, got status %d", loginMaxAttempts, w.Code)
	}
}
