// SPDX-License-Identifier: GPL-3.0-or-later

package alert

import (
	"testing"
	"time"
)

// fakeClock is a controllable Clock for deterministic windowing.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// fakeResolver is a fake inventory: a static IP -> device map.
type fakeResolver struct{ devices map[string]DeviceInfo }

func (f fakeResolver) Lookup(ip string) (DeviceInfo, bool) {
	d, ok := f.devices[ip]
	return d, ok
}

var base = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// Threshold crossing on repeated blocked hits from one client fires exactly one
// alert, enriched with the device (IP + MAC + hostname) from the inventory.
func TestRecordBlocked_ThresholdCrossing_WithDevice(t *testing.T) {
	clk := &fakeClock{t: base}
	res := fakeResolver{devices: map[string]DeviceInfo{
		"192.168.1.50": {IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:50", Hostname: "roshan-laptop"},
	}}
	a := NewAlerter(Config{Threshold: 3, Window: 10 * time.Minute}, res, clk)

	if !a.Enabled() {
		t.Fatal("alerter with positive threshold should be enabled")
	}

	// First two hits stay below the threshold.
	for i := 1; i <= 2; i++ {
		if al, fired := a.RecordBlocked("192.168.1.50", "c2.evil.com"); fired {
			t.Fatalf("hit %d should not fire an alert (got %+v)", i, al)
		}
	}

	al, fired := a.RecordBlocked("192.168.1.50", "beacon.evil.com")
	if !fired {
		t.Fatal("third hit should cross the threshold and fire")
	}
	if al.Device.IP != "192.168.1.50" || al.Device.MAC != "aa:bb:cc:dd:ee:50" || al.Device.Hostname != "roshan-laptop" {
		t.Errorf("alert not enriched with device: %+v", al.Device)
	}
	if al.Hits != 3 || al.Threshold != 3 {
		t.Errorf("expected hits=3 threshold=3, got hits=%d threshold=%d", al.Hits, al.Threshold)
	}
	if !al.FiredAt.Equal(base) || !al.FirstHit.Equal(base) {
		t.Errorf("expected FiredAt=FirstHit=base, got fired=%v first=%v", al.FiredAt, al.FirstHit)
	}
	if al.Domain != "beacon.evil.com" {
		t.Errorf("expected triggering domain beacon.evil.com, got %q", al.Domain)
	}

	// Device is now suspected and surfaced by the status accessor.
	if !a.IsSuspected("192.168.1.50") {
		t.Error("device should be marked suspected after firing")
	}
	susp := a.Suspected()
	if len(susp) != 1 || susp[0].Device.Hostname != "roshan-laptop" {
		t.Errorf("Suspected() = %+v, want one entry for roshan-laptop", susp)
	}

	// The counter resets on fire: a single further hit must not re-fire.
	if _, fired := a.RecordBlocked("192.168.1.50", "c2.evil.com"); fired {
		t.Error("counter should reset after firing; single hit re-fired")
	}
}

// Below the threshold, no alert is produced and nothing is suspected.
func TestRecordBlocked_BelowThreshold_NoAlert(t *testing.T) {
	clk := &fakeClock{t: base}
	a := NewAlerter(Config{Threshold: 5, Window: 10 * time.Minute}, fakeResolver{}, clk)

	for i := 1; i <= 4; i++ {
		if _, fired := a.RecordBlocked("10.0.0.9", "malware.example"); fired {
			t.Fatalf("hit %d should not fire below a threshold of 5", i)
		}
	}
	if a.IsSuspected("10.0.0.9") {
		t.Error("device below threshold should not be suspected")
	}
	if got := a.Suspected(); len(got) != 0 {
		t.Errorf("expected no suspected devices, got %+v", got)
	}
}

// A client that is unknown to the inventory still fires, but the alert is
// IP-only (no MAC / hostname).
func TestRecordBlocked_UnknownDevice_IPOnly(t *testing.T) {
	clk := &fakeClock{t: base}

	cases := map[string]DeviceResolver{
		"empty inventory": fakeResolver{devices: map[string]DeviceInfo{}},
		"nil resolver":    nil,
	}
	for name, res := range cases {
		t.Run(name, func(t *testing.T) {
			a := NewAlerter(Config{Threshold: 2, Window: time.Minute}, res, clk)
			a.RecordBlocked("172.16.0.4", "c2.evil.com")
			al, fired := a.RecordBlocked("172.16.0.4", "c2.evil.com")
			if !fired {
				t.Fatal("expected alert to fire at threshold")
			}
			if al.Device.IP != "172.16.0.4" {
				t.Errorf("expected IP-only device IP 172.16.0.4, got %q", al.Device.IP)
			}
			if al.Device.MAC != "" || al.Device.Hostname != "" {
				t.Errorf("unknown device should have empty MAC/hostname, got %+v", al.Device)
			}
		})
	}
}

// A disabled alerter (threshold <= 0) never fires, no matter how many hits.
func TestRecordBlocked_Disabled_Off(t *testing.T) {
	clk := &fakeClock{t: base}
	for _, thr := range []int{0, -1} {
		a := NewAlerter(Config{Threshold: thr, Window: time.Minute}, fakeResolver{}, clk)
		if a.Enabled() {
			t.Errorf("threshold %d should be disabled", thr)
		}
		for i := 0; i < 100; i++ {
			if _, fired := a.RecordBlocked("192.168.1.1", "c2.evil.com"); fired {
				t.Fatalf("disabled alerter (threshold %d) fired on hit %d", thr, i)
			}
		}
		if got := a.Suspected(); len(got) != 0 {
			t.Errorf("disabled alerter should have no suspected devices, got %+v", got)
		}
	}
}

// Hits that age out of the sliding window are not counted toward the threshold.
func TestRecordBlocked_WindowSliding(t *testing.T) {
	clk := &fakeClock{t: base}
	a := NewAlerter(Config{Threshold: 3, Window: 10 * time.Minute}, nil, clk)

	a.RecordBlocked("192.168.1.7", "c2.evil.com") // hit @ base
	clk.Advance(1 * time.Minute)
	a.RecordBlocked("192.168.1.7", "c2.evil.com") // hit @ base+1m

	// Jump past the window: both earlier hits expire.
	clk.Advance(11 * time.Minute) // now base+12m, cutoff base+2m
	if _, fired := a.RecordBlocked("192.168.1.7", "c2.evil.com"); fired {
		t.Fatal("hit should not fire after earlier hits aged out of the window")
	}

	// Two more hits inside the fresh window cross the threshold.
	clk.Advance(1 * time.Minute)
	a.RecordBlocked("192.168.1.7", "c2.evil.com") // count 2 @ base+13m
	clk.Advance(1 * time.Minute)
	al, fired := a.RecordBlocked("192.168.1.7", "c2.evil.com") // count 3 @ base+14m
	if !fired {
		t.Fatal("three in-window hits should cross the threshold")
	}
	if al.Hits != 3 {
		t.Errorf("expected hits=3, got %d", al.Hits)
	}
	wantFirst := base.Add(12 * time.Minute)
	if !al.FirstHit.Equal(wantFirst) {
		t.Errorf("FirstHit = %v, want %v (window start)", al.FirstHit, wantFirst)
	}
}

// Distinct clients are counted independently.
func TestRecordBlocked_PerClientIndependent(t *testing.T) {
	clk := &fakeClock{t: base}
	a := NewAlerter(Config{Threshold: 2, Window: time.Minute}, nil, clk)

	a.RecordBlocked("10.0.0.1", "c2.evil.com")
	// A single hit from a different client must not push .1 over on its own.
	if _, fired := a.RecordBlocked("10.0.0.2", "c2.evil.com"); fired {
		t.Fatal("second client should not fire on its first hit")
	}
	if _, fired := a.RecordBlocked("10.0.0.1", "c2.evil.com"); !fired {
		t.Fatal("first client should fire on its own second hit")
	}
}

// The optional sink receives each fired alert.
func TestRecordBlocked_SinkInvoked(t *testing.T) {
	clk := &fakeClock{t: base}
	a := NewAlerter(Config{Threshold: 1, Window: time.Minute}, nil, clk)

	got := make(chan Alert, 1)
	a.SetSink(func(al Alert) { got <- al })

	a.RecordBlocked("10.0.0.5", "c2.evil.com")
	select {
	case al := <-got:
		if al.Device.IP != "10.0.0.5" {
			t.Errorf("sink got unexpected alert: %+v", al)
		}
	default:
		t.Fatal("sink was not invoked on fire")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("DEVICE_ALERT_THRESHOLD", "5")
	t.Setenv("DEVICE_ALERT_WINDOW", "2m")
	cfg := ConfigFromEnv()
	if cfg.Threshold != 5 {
		t.Errorf("expected threshold 5, got %d", cfg.Threshold)
	}
	if cfg.Window != 2*time.Minute {
		t.Errorf("expected window 2m, got %v", cfg.Window)
	}
}

func TestConfigFromEnv_DefaultOff(t *testing.T) {
	t.Setenv("DEVICE_ALERT_THRESHOLD", "")
	t.Setenv("DEVICE_ALERT_WINDOW", "")
	cfg := ConfigFromEnv()
	if cfg.Threshold != 0 {
		t.Errorf("threshold should default to 0 (off), got %d", cfg.Threshold)
	}
	if cfg.Window != DefaultWindow {
		t.Errorf("window should default to %v, got %v", DefaultWindow, cfg.Window)
	}
	if NewAlerter(cfg, nil, nil).Enabled() {
		t.Error("default config should produce a disabled alerter")
	}
}

func TestConfigFromEnv_InvalidValuesIgnored(t *testing.T) {
	t.Setenv("DEVICE_ALERT_THRESHOLD", "not-a-number")
	t.Setenv("DEVICE_ALERT_WINDOW", "garbage")
	cfg := ConfigFromEnv()
	if cfg.Threshold != 0 {
		t.Errorf("invalid threshold should leave default 0, got %d", cfg.Threshold)
	}
	if cfg.Window != DefaultWindow {
		t.Errorf("invalid window should leave default, got %v", cfg.Window)
	}
}
