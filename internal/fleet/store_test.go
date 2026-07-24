// SPDX-License-Identifier: GPL-3.0-or-later

package fleet

import (
	"testing"
	"time"
)

// fakeClock is a deterministic, mutable clock for tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestStore(stale time.Duration) (*Store, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return NewStore(stale, clk.Now), clk
}

func TestStore_RecordUpdatesSite(t *testing.T) {
	s, _ := newTestStore(90 * time.Second)

	s.Record(Heartbeat{SiteID: "box-1", Name: "Clinic A", QPS: 12.5, BlockedPercent: 8.0})

	view := s.Snapshot()
	if view.Total != 1 {
		t.Fatalf("expected 1 site, got %d", view.Total)
	}
	site := view.Sites[0]
	if site.SiteID != "box-1" || site.Name != "Clinic A" {
		t.Fatalf("unexpected site identity: %+v", site)
	}
	if site.QPS != 12.5 || site.BlockedPercent != 8.0 {
		t.Errorf("metadata not stored: qps=%v blocked=%v", site.QPS, site.BlockedPercent)
	}
	if site.Status != StatusUp {
		t.Errorf("expected fresh site to be up, got %q", site.Status)
	}

	// A second heartbeat for the same id updates in place (no duplicate).
	s.Record(Heartbeat{SiteID: "box-1", QPS: 20})
	view = s.Snapshot()
	if view.Total != 1 {
		t.Fatalf("expected same site updated, got %d sites", view.Total)
	}
	if view.Sites[0].QPS != 20 {
		t.Errorf("expected updated qps 20, got %v", view.Sites[0].QPS)
	}
}

func TestStore_SnapshotConsolidatedView(t *testing.T) {
	s, _ := newTestStore(90 * time.Second)

	s.Record(Heartbeat{SiteID: "box-b"})
	s.Record(Heartbeat{SiteID: "box-a"})
	s.Record(Heartbeat{SiteID: "box-c"})

	view := s.Snapshot()
	if view.Total != 3 || view.Up != 3 || view.Down != 0 {
		t.Fatalf("unexpected counts: total=%d up=%d down=%d", view.Total, view.Up, view.Down)
	}
	// Deterministic ordering by site id.
	want := []string{"box-a", "box-b", "box-c"}
	for i, id := range want {
		if view.Sites[i].SiteID != id {
			t.Errorf("site %d: expected %q, got %q", i, id, view.Sites[i].SiteID)
		}
	}
	if view.StaleAfterSeconds != 90 {
		t.Errorf("expected stale_after 90s, got %d", view.StaleAfterSeconds)
	}
}

func TestStore_StaleDetectionFlipsToDown(t *testing.T) {
	s, clk := newTestStore(90 * time.Second)

	s.Record(Heartbeat{SiteID: "box-1"})

	// Still within the window: up.
	clk.Advance(60 * time.Second)
	if got := s.Snapshot().Sites[0].Status; got != StatusUp {
		t.Fatalf("expected up within window, got %q", got)
	}

	// Past the stale threshold: flips to down.
	clk.Advance(60 * time.Second) // total 120s > 90s
	view := s.Snapshot()
	if got := view.Sites[0].Status; got != StatusDown {
		t.Fatalf("expected down after stale window, got %q", got)
	}
	if view.Up != 0 || view.Down != 1 {
		t.Errorf("expected up=0 down=1, got up=%d down=%d", view.Up, view.Down)
	}

	// A fresh heartbeat revives it.
	s.Record(Heartbeat{SiteID: "box-1"})
	if got := s.Snapshot().Sites[0].Status; got != StatusUp {
		t.Errorf("expected up after fresh heartbeat, got %q", got)
	}
}

func TestStore_BlocklistFreshness(t *testing.T) {
	s, clk := newTestStore(90 * time.Second)

	updated := clk.Now().Add(-30 * time.Minute)
	s.Record(Heartbeat{SiteID: "box-1", BlocklistUpdatedAt: &updated})

	site := s.Snapshot().Sites[0]
	if site.BlocklistAgeSeconds == nil {
		t.Fatal("expected blocklist age to be computed")
	}
	if *site.BlocklistAgeSeconds != 1800 {
		t.Errorf("expected blocklist age 1800s, got %d", *site.BlocklistAgeSeconds)
	}
}
