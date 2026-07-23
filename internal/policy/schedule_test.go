// SPDX-License-Identifier: GPL-3.0-or-later
package policy

import (
	"strings"
	"testing"
	"time"
)

// fixedClock returns a clock function that always reports the same instant, so
// scheduled-policy evaluation is fully deterministic.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("load location %q: %v", name, err)
	}
	return loc
}

// engineAt builds an engine pinned to a fixed instant and loaded with policies.
func engineAt(t *testing.T, now time.Time, policies ...Policy) *Engine {
	t.Helper()
	e := NewPolicyEngineWithClock(fixedClock(now))
	if err := e.LoadPolicies(policies); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	return e
}

// TestEvaluate_UnscheduledAlwaysActive proves the fast path is unchanged: a
// policy with no schedule matches regardless of the clock.
func TestEvaluate_UnscheduledAlwaysActive(t *testing.T) {
	p := Policy{ID: "always", Action: "BLOCK", Priority: 100, Domains: []string{"blocked.com"}}
	for _, now := range []time.Time{
		time.Date(2026, 7, 20, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 20, 15, 30, 0, 0, time.UTC),
		time.Date(2026, 12, 25, 23, 59, 0, 0, time.UTC),
	} {
		e := engineAt(t, now, p)
		if d, _ := e.Evaluate("blocked.com"); d.Action != ActionDeny {
			t.Fatalf("unscheduled policy should always block; got %v at %v", d.Action, now)
		}
	}
}

func TestEvaluate_ActiveInsideWindow(t *testing.T) {
	ist := mustLoad(t, "Asia/Kolkata")
	p := Policy{
		ID: "work-hours", Action: "BLOCK", Priority: 100,
		Domains:   []string{"social.example.com"},
		StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata",
	}

	// 12:00 IST is inside [09:00,17:00) -> active -> blocked.
	e := engineAt(t, time.Date(2026, 7, 20, 12, 0, 0, 0, ist), p)
	if d, _ := e.Evaluate("social.example.com"); d.Action != ActionDeny {
		t.Fatalf("expected block inside window, got %v", d.Action)
	}
}

func TestEvaluate_InactiveOutsideWindow(t *testing.T) {
	ist := mustLoad(t, "Asia/Kolkata")
	p := Policy{
		ID: "work-hours", Action: "BLOCK", Priority: 100,
		Domains:   []string{"social.example.com"},
		StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata",
	}

	// 20:00 IST is outside the window -> inactive -> default allow.
	e := engineAt(t, time.Date(2026, 7, 20, 20, 0, 0, 0, ist), p)
	if d, _ := e.Evaluate("social.example.com"); d.Action != ActionAllow {
		t.Fatalf("expected allow outside window, got %v", d.Action)
	}
}

func TestEvaluate_WindowBoundaries(t *testing.T) {
	ist := mustLoad(t, "Asia/Kolkata")
	p := Policy{
		ID: "b", Action: "BLOCK", Priority: 100, Domains: []string{"x.com"},
		StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata",
	}
	// Start is inclusive.
	if d, _ := engineAt(t, time.Date(2026, 7, 20, 9, 0, 0, 0, ist), p).Evaluate("x.com"); d.Action != ActionDeny {
		t.Fatalf("expected block at inclusive start 09:00, got %v", d.Action)
	}
	// End is exclusive.
	if d, _ := engineAt(t, time.Date(2026, 7, 20, 17, 0, 0, 0, ist), p).Evaluate("x.com"); d.Action != ActionAllow {
		t.Fatalf("expected allow at exclusive end 17:00, got %v", d.Action)
	}
}

// TestEvaluate_TimezoneHandling proves the window is evaluated in the policy's
// timezone, not UTC: the same UTC instant is inside the window under one
// timezone and outside it under another.
func TestEvaluate_TimezoneHandling(t *testing.T) {
	// 12:00 UTC.
	nowUTC := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	// Window 09:00-17:00. In UTC, 12:00 is inside -> block.
	pUTC := Policy{
		ID: "utc", Action: "BLOCK", Priority: 100, Domains: []string{"x.com"},
		StartTime: "09:00", EndTime: "17:00", Timezone: "UTC",
	}
	if d, _ := engineAt(t, nowUTC, pUTC).Evaluate("x.com"); d.Action != ActionDeny {
		t.Fatalf("UTC: expected block at 12:00 UTC, got %v", d.Action)
	}

	// Same instant is 17:30 IST, which is past 17:00 -> allow.
	pIST := Policy{
		ID: "ist", Action: "BLOCK", Priority: 100, Domains: []string{"x.com"},
		StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata",
	}
	if d, _ := engineAt(t, nowUTC, pIST).Evaluate("x.com"); d.Action != ActionAllow {
		t.Fatalf("IST: expected allow (17:30 IST past window), got %v", d.Action)
	}
}

// TestEvaluate_DayOfWeek is calendar-independent: it derives the allowed and
// disallowed day names from the pinned instant itself.
func TestEvaluate_DayOfWeek(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	today := strings.ToLower(base.Weekday().String()[:3]) // e.g. "mon"
	tomorrow := strings.ToLower(base.AddDate(0, 0, 1).Weekday().String()[:3])

	// Active on today's weekday -> block.
	pToday := Policy{
		ID: "today", Action: "BLOCK", Priority: 100, Domains: []string{"x.com"},
		ScheduleDays: []string{today}, Timezone: "UTC",
	}
	if d, _ := engineAt(t, base, pToday).Evaluate("x.com"); d.Action != ActionDeny {
		t.Fatalf("expected block on scheduled day %q, got %v", today, d.Action)
	}

	// Scheduled only for tomorrow -> inactive today -> allow.
	pTomorrow := Policy{
		ID: "tomorrow", Action: "BLOCK", Priority: 100, Domains: []string{"x.com"},
		ScheduleDays: []string{tomorrow}, Timezone: "UTC",
	}
	if d, _ := engineAt(t, base, pTomorrow).Evaluate("x.com"); d.Action != ActionAllow {
		t.Fatalf("expected allow off scheduled day (%q only), got %v", tomorrow, d.Action)
	}
}

// TestEvaluate_DayAndWindowCombined requires both the day and the window to
// match.
func TestEvaluate_DayAndWindowCombined(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	today := strings.ToLower(base.Weekday().String()[:3])

	p := Policy{
		ID: "combo", Action: "BLOCK", Priority: 100, Domains: []string{"x.com"},
		ScheduleDays: []string{today}, StartTime: "09:00", EndTime: "17:00", Timezone: "UTC",
	}
	// Right day, inside window -> block.
	if d, _ := engineAt(t, base, p).Evaluate("x.com"); d.Action != ActionDeny {
		t.Fatalf("expected block on day+window, got %v", d.Action)
	}
	// Right day, outside window -> allow.
	outside := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	if d, _ := engineAt(t, outside, p).Evaluate("x.com"); d.Action != ActionAllow {
		t.Fatalf("expected allow on right day but outside window, got %v", d.Action)
	}
}

// TestEvaluate_OvernightWindow covers a window that crosses midnight.
func TestEvaluate_OvernightWindow(t *testing.T) {
	p := Policy{
		ID: "night", Action: "BLOCK", Priority: 100, Domains: []string{"x.com"},
		StartTime: "22:00", EndTime: "06:00", Timezone: "UTC",
	}
	cases := []struct {
		hour int
		want Action
	}{
		{23, ActionDeny},  // after start, before midnight
		{2, ActionDeny},   // after midnight, before end
		{5, ActionDeny},   // just before end
		{6, ActionAllow},  // exclusive end
		{12, ActionAllow}, // midday, outside
		{21, ActionAllow}, // just before start
	}
	for _, tc := range cases {
		now := time.Date(2026, 7, 20, tc.hour, 0, 0, 0, time.UTC)
		if d, _ := engineAt(t, now, p).Evaluate("x.com"); d.Action != tc.want {
			t.Fatalf("overnight window at %02d:00: want %v, got %v", tc.hour, tc.want, d.Action)
		}
	}
}

// TestEvaluate_ScheduledFallsThroughToParent proves an inactive scheduled child
// policy does not shadow an always-on parent-domain rule.
func TestEvaluate_ScheduledFallsThroughToParent(t *testing.T) {
	child := Policy{
		ID: "child", Action: "ALLOW", Priority: 200, Domains: []string{"ads.example.com"},
		StartTime: "09:00", EndTime: "17:00", Timezone: "UTC", // inactive at 20:00
	}
	parent := Policy{
		ID: "parent", Action: "BLOCK", Priority: 10, Domains: []string{"example.com"},
	}

	// 20:00 UTC: child inactive, so the always-on parent BLOCK applies.
	e := engineAt(t, time.Date(2026, 7, 20, 20, 0, 0, 0, time.UTC), child, parent)
	if d, _ := e.Evaluate("ads.example.com"); d.Action != ActionDeny || d.PolicyID != "parent" {
		t.Fatalf("expected fall-through to parent BLOCK, got action=%v id=%q", d.Action, d.PolicyID)
	}

	// 12:00 UTC: child active (higher priority ALLOW) wins over parent.
	e = engineAt(t, time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC), child, parent)
	if d, _ := e.Evaluate("ads.example.com"); d.Action != ActionAllow || d.PolicyID != "child" {
		t.Fatalf("expected active child ALLOW to win, got action=%v id=%q", d.Action, d.PolicyID)
	}
}

func TestValidatePolicy_Schedule(t *testing.T) {
	valid := []Policy{
		{ID: "a", Action: "BLOCK", StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata"},
		{ID: "b", Action: "BLOCK", ScheduleDays: []string{"mon", "Friday"}},
		{ID: "c", Action: "BLOCK", StartTime: "22:00", EndTime: "06:00"},
		{ID: "d", Action: "BLOCK"}, // no schedule
	}
	for _, p := range valid {
		if err := ValidatePolicy(&p); err != nil {
			t.Errorf("expected valid policy %s, got error: %v", p.ID, err)
		}
	}

	invalid := []Policy{
		{ID: "tz", Action: "BLOCK", StartTime: "09:00", EndTime: "17:00", Timezone: "Mars/Phobos"},
		{ID: "day", Action: "BLOCK", ScheduleDays: []string{"funday"}},
		{ID: "hhmm", Action: "BLOCK", StartTime: "9am", EndTime: "5pm"},
		{ID: "half", Action: "BLOCK", StartTime: "09:00"}, // end missing
		{ID: "equal", Action: "BLOCK", StartTime: "09:00", EndTime: "09:00"},
		{ID: "range", Action: "BLOCK", StartTime: "25:00", EndTime: "26:00"},
	}
	for _, p := range invalid {
		if err := ValidatePolicy(&p); err == nil {
			t.Errorf("expected error for invalid schedule policy %s, got nil", p.ID)
		}
	}
}

// TestCompiledSchedule_NilAlwaysActive documents that a nil schedule (the
// unscheduled default) is always active.
func TestCompiledSchedule_NilAlwaysActive(t *testing.T) {
	var s *compiledSchedule
	if !s.active(time.Now()) {
		t.Fatal("nil schedule must always be active")
	}
	p := Policy{ID: "x", Action: "BLOCK"}
	cs, err := compileSchedule(&p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cs != nil {
		t.Fatalf("expected nil compiled schedule for unscheduled policy, got %+v", cs)
	}
}
