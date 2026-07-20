//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later

package inventory

// readARPTable is a graceful no-op on non-Linux platforms: the kernel ARP
// table is not read, so ARP-based discovery contributes no entries. DHCP lease
// parsing (if configured) still works everywhere.
func readARPTable() []arpEntry { return nil }
