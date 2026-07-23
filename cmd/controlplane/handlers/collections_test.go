// SPDX-License-Identifier: GPL-3.0-or-later
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decodeCollection(t *testing.T, w *httptest.ResponseRecorder) ResponseCollectionSingle {
	t.Helper()
	var resp ResponseCollectionSingle
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode collection: %v (body=%s)", err, w.Body.String())
	}
	return resp
}

func TestListCollections_DefaultsOff(t *testing.T) {
	h := newCatalogTestHandler(t) // built-in catalog has app collections
	r := newCatalogRouter(h)

	w := doRawJSON(t, r, http.MethodGet, "/api/v1/collections", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp ResponseCollectionList
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.List) == 0 {
		t.Fatal("expected built-in collections")
	}
	if resp.Data.EnabledCollections != 0 {
		t.Errorf("expected 0 enabled collections by default, got %d", resp.Data.EnabledCollections)
	}
}

// TestToggleCollection_BlocksBundle enables the TikTok collection and verifies its whole
// curated domain bundle is blocked as one toggle (I-052).
func TestToggleCollection_BlocksBundle(t *testing.T) {
	h := newCatalogTestHandler(t)
	r := newCatalogRouter(h)

	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/collections/tiktok", `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enable expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	resp := decodeCollection(t, w)
	if !resp.Data.Enabled {
		t.Error("expected collection enabled")
	}
	if resp.Data.DomainsCount == 0 {
		t.Error("expected the TikTok bundle to contribute domains")
	}

	// The whole bundle blocks under one toggle.
	for _, d := range []string{"tiktok.com", "tiktokcdn.com"} {
		if blocked, _ := h.Store.Blocklist.IsBlocked(d); !blocked {
			t.Errorf("expected %s blocked after enabling TikTok collection", d)
		}
	}
	// A subdomain of a bundled domain is caught by the parent-walk matcher.
	if blocked, _ := h.Store.Blocklist.IsBlocked("www.tiktok.com"); !blocked {
		t.Error("expected subdomain www.tiktok.com blocked")
	}
}

func TestToggleCollection_TogglePersistsAndDisables(t *testing.T) {
	h := newCatalogTestHandler(t)
	r := newCatalogRouter(h)

	// Enable then disable.
	if w := doRawJSON(t, r, http.MethodPatch, "/api/v1/collections/instagram", `{"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("enable expected 200, got %d", w.Code)
	}
	if blocked, _ := h.Store.Blocklist.IsBlocked("instagram.com"); !blocked {
		t.Fatal("expected instagram.com blocked after enable")
	}

	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/collections/instagram", `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("disable expected 200, got %d", w.Code)
	}
	resp := decodeCollection(t, w)
	if resp.Data.Enabled || resp.Data.DomainsCount != 0 {
		t.Errorf("expected disabled with 0 domains, got enabled=%v count=%d", resp.Data.Enabled, resp.Data.DomainsCount)
	}
	if blocked, _ := h.Store.Blocklist.IsBlocked("instagram.com"); blocked {
		t.Error("expected instagram.com NOT blocked after disable")
	}

	// Persisted state reflects in the list.
	lw := doRawJSON(t, r, http.MethodGet, "/api/v1/collections", "")
	var list ResponseCollectionList
	if err := json.Unmarshal(lw.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Data.EnabledCollections != 0 {
		t.Errorf("expected 0 enabled after disable, got %d", list.Data.EnabledCollections)
	}
}

func TestToggleCollection_UnknownName(t *testing.T) {
	h := newCatalogTestHandler(t)
	r := newCatalogRouter(h)

	w := doRawJSON(t, r, http.MethodPatch, "/api/v1/collections/nope", `{"enabled":true}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown collection, got %d", w.Code)
	}
}
