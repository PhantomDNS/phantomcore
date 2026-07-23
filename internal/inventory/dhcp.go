// SPDX-License-Identifier: GPL-3.0-or-later

package inventory

import (
	"bufio"
	"bytes"
	"strings"
)

// dhcpLease is a single binding read from a dnsmasq-style lease file.
type dhcpLease struct {
	IP       string
	MAC      string
	Hostname string
}

// parseDHCPLeases parses a dnsmasq-style DHCP lease file. Each active lease is
// a whitespace-separated line:
//
//	<expiry-epoch> <mac> <ip> <hostname> <client-id>
//
// e.g. "1750000000 aa:bb:cc:dd:ee:ff 192.168.1.100 my-laptop 01:aa:bb:cc:dd:ee:ff"
//
// A hostname of "*" means unknown and is treated as empty. Parsing is a pure
// function over the file bytes so it is testable without real files.
func parseDHCPLeases(data []byte) []dhcpLease {
	var out []dhcpLease
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Need at least expiry, mac and ip.
		if len(fields) < 3 {
			continue
		}
		mac := strings.ToLower(fields[1])
		ip := fields[2]
		hostname := ""
		if len(fields) >= 4 && fields[3] != "*" {
			hostname = fields[3]
		}
		out = append(out, dhcpLease{IP: ip, MAC: mac, Hostname: hostname})
	}
	return out
}
