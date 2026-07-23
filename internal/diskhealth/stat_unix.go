// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package diskhealth

import (
	"fmt"
	"syscall"
	"time"
)

// readDiskStat inspects the filesystem backing dir via syscall.Statfs and
// returns a point-in-time capacity sample. Byte counts are derived from the
// filesystem block size. Bavail (blocks available to unprivileged users) is used
// for free space so the reading matches what the application can actually write.
func readDiskStat(dir string) (diskStat, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return diskStat{}, err
	}

	// Bsize is signed on some platforms; normalise to uint64. Guard against a
	// negative value (never expected from a real filesystem) before the cast.
	if fs.Bsize < 0 {
		return diskStat{}, fmt.Errorf("readDiskStat: negative block size %d from statfs", fs.Bsize)
	}
	bsize := uint64(fs.Bsize)
	total := uint64(fs.Blocks) * bsize
	free := uint64(fs.Bavail) * bsize

	return diskStat{
		Path:       dir,
		TotalBytes: total,
		FreeBytes:  free,
		SampledAt:  time.Now(),
	}, nil
}
