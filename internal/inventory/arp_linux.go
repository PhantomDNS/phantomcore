//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later

package inventory

import "os"

// procNetARP is the kernel-exported ARP table on Linux. It is a package
// variable only so tests could point it elsewhere if ever needed; production
// code never overrides it.
var procNetARP = "/proc/net/arp"

// readARPTable reads the live ARP table on Linux. On read failure it returns
// nil so a refresh cycle simply observes no ARP entries.
func readARPTable() []arpEntry {
	data, err := os.ReadFile(procNetARP)
	if err != nil {
		return nil
	}
	return parseARP(data)
}
