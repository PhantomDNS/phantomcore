// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

package diskhealth

// readWear reports no wear information on non-Linux platforms. Wear/SMART is
// best-effort only, so nil is the expected graceful-degradation result.
func readWear(_ string) *WearInfo {
	return nil
}
