// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package diskhealth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLifeTime(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantPct int
		wantOK  bool
	}{
		{"fresh card", "0x01 0x01\n", 0, true},
		{"half worn", "0x06 0x06\n", 50, true},
		{"worst of two wins", "0x02 0x07\n", 60, true},
		{"exceeded life", "0x0B 0x0B\n", 100, true},
		{"undefined values", "0x00 0x00\n", 0, false},
		{"single value", "0x0A\n", 90, true},
		{"garbage", "not-hex\n", 0, false},
		{"empty", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pct, ok := parseLifeTime(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && pct != tt.wantPct {
				t.Errorf("pct = %d, want %d", pct, tt.wantPct)
			}
		})
	}
}

func TestReadWearFromSysfsFixture(t *testing.T) {
	// Build a fake sysfs tree: <root>/mmcblk0/device/life_time
	root := t.TempDir()
	devDir := filepath.Join(root, "mmcblk0", "device")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(devDir, "life_time"), []byte("0x03 0x03\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := wearGlob
	wearGlob = filepath.Join(root, "mmcblk*", "device", "life_time")
	defer func() { wearGlob = orig }()

	w := readWear("/data")
	if w == nil {
		t.Fatal("expected wear info, got nil")
	}
	if w.Device != "mmcblk0" {
		t.Errorf("device = %q, want mmcblk0", w.Device)
	}
	if w.LifeUsedPct != 20 {
		t.Errorf("life used = %d, want 20", w.LifeUsedPct)
	}
}

func TestReadWearNoDevice(t *testing.T) {
	orig := wearGlob
	wearGlob = filepath.Join(t.TempDir(), "nope*", "life_time")
	defer func() { wearGlob = orig }()

	if w := readWear("/data"); w != nil {
		t.Errorf("expected nil wear when no device, got %+v", w)
	}
}
