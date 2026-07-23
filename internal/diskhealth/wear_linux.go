// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package diskhealth

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// wearGlob points at eMMC/SD life-time estimation exposed by the MMC subsystem.
// Overridable in tests. The kernel exposes one or two hex "life time" values
// (JEDEC eMMC 5.0 DEVICE_LIFE_TIME_EST_TYP_A/B): 0x01 => 0-10% of rated write
// life consumed, 0x0A => 90-100%, 0x0B => exceeded.
var wearGlob = "/sys/block/mmcblk*/device/life_time"

// readWear makes a best-effort attempt to read flash wear for an eMMC/SD device.
// It returns nil (not an error) whenever the information is unavailable, so
// callers degrade gracefully on plain disks or where sysfs lacks the attribute.
func readWear(_ string) *WearInfo {
	matches, err := filepath.Glob(wearGlob)
	if err != nil || len(matches) == 0 {
		return nil
	}

	for _, path := range matches {
		// #nosec G304 -- path comes from globbing a fixed sysfs prefix, not user input.
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		pct, ok := parseLifeTime(string(data))
		if !ok {
			continue
		}
		// path is .../mmcblkX/device/life_time; device name is 3 dirs up.
		dev := filepath.Base(filepath.Dir(filepath.Dir(path)))
		return &WearInfo{
			Device:      dev,
			LifeUsedPct: pct,
			Source:      "emmc-life_time",
		}
	}
	return nil
}

// parseLifeTime turns a "0x01 0x02" life-time line into an estimated percent of
// rated write life consumed, using the higher (worse) of the reported values.
func parseLifeTime(s string) (int, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, false
	}
	worst := -1
	for _, f := range fields {
		v, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimPrefix(f, "0x"), "0X"), 16, 32)
		if err != nil {
			continue
		}
		if v <= 0 {
			continue // 0x00 means "not defined"
		}
		var pct int
		if v >= 0x0B {
			pct = 100 // exceeded estimated life
		} else {
			pct = int(v-1) * 10 // 0x01 => 0%, 0x0A => 90%
		}
		if pct > worst {
			worst = pct
		}
	}
	if worst < 0 {
		return 0, false
	}
	return worst, true
}
