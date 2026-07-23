// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !unix

package diskhealth

// readDiskStat is unsupported on non-unix platforms. The Monitor treats the
// error as non-fatal and simply keeps its prior status.
func readDiskStat(dir string) (diskStat, error) {
	return diskStat{}, ErrUnsupported
}
