// SPDX-License-Identifier: GPL-3.0-or-later

package inventory

import (
	"bufio"
	"bytes"
	"strings"
)

// arpEntry is a single resolved IP -> MAC binding from the ARP table.
type arpEntry struct {
	IP  string
	MAC string
}

// emptyMAC is the placeholder MAC the kernel reports for incomplete entries.
const emptyMAC = "00:00:00:00:00:00"

// parseARP parses the contents of a Linux /proc/net/arp file into resolved
// entries. It is a pure function over the file bytes so it can be tested
// without touching the real filesystem or requiring privileges.
//
// The file looks like:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
//	192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
//
// The header line, incomplete entries (Flags 0x0) and placeholder MACs are
// skipped.
func parseARP(data []byte) []arpEntry {
	var out []arpEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Skip the column header.
		if strings.HasPrefix(line, "IP address") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		flags := fields[2]
		mac := strings.ToLower(fields[3])
		// Flags 0x0 means the entry is incomplete (no MAC learned yet).
		if flags == "0x0" {
			continue
		}
		if mac == "" || mac == emptyMAC {
			continue
		}
		out = append(out, arpEntry{IP: ip, MAC: mac})
	}
	return out
}
