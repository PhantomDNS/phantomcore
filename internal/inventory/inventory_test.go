// SPDX-License-Identifier: GPL-3.0-or-later

package inventory

import (
	"testing"
	"time"
)

// fakeClock is a controllable Clock for deterministic seen timestamps.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestParseARP(t *testing.T) {
	input := []byte(`IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:01     *        eth0
192.168.1.2      0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0

10.0.0.5         0x1         0x2         de:ad:be:ef:00:05     *        wlan0
garbage line without enough fields
`)

	got := parseARP(input)

	want := []arpEntry{
		{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"}, // MAC lowercased
		{IP: "192.168.1.2", MAC: "aa:bb:cc:dd:ee:02"},
		{IP: "10.0.0.5", MAC: "de:ad:be:ef:00:05"},
	}
	if len(got) != len(want) {
		t.Fatalf("parseARP returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseARP_Empty(t *testing.T) {
	// Header only -> no entries.
	if got := parseARP([]byte("IP address  HW type  Flags  HW address  Mask  Device\n")); len(got) != 0 {
		t.Errorf("expected 0 entries from header-only input, got %d", len(got))
	}
	if got := parseARP(nil); len(got) != 0 {
		t.Errorf("expected 0 entries from nil input, got %d", len(got))
	}
}

func TestParseDHCPLeases(t *testing.T) {
	input := []byte(`1750000000 AA:BB:CC:DD:EE:01 192.168.1.100 my-laptop 01:aa:bb:cc:dd:ee:01
1750000500 aa:bb:cc:dd:ee:02 192.168.1.101 * 01:aa:bb:cc:dd:ee:02
1750000900 aa:bb:cc:dd:ee:03 192.168.1.102 printer

short line
`)

	got := parseDHCPLeases(input)

	want := []dhcpLease{
		{IP: "192.168.1.100", MAC: "aa:bb:cc:dd:ee:01", Hostname: "my-laptop"},
		{IP: "192.168.1.101", MAC: "aa:bb:cc:dd:ee:02", Hostname: ""}, // "*" -> empty
		{IP: "192.168.1.102", MAC: "aa:bb:cc:dd:ee:03", Hostname: "printer"},
	}
	if len(got) != len(want) {
		t.Fatalf("parseDHCPLeases returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("lease[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMerge_NewAndUpdate(t *testing.T) {
	t0 := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	clk := &fakeClock{t: t0}
	inv := New(Config{Enabled: true}, clk)

	// First cycle: ARP sees the device (MAC only).
	inv.merge([]arpEntry{{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:10"}}, nil)

	devs := inv.Devices()
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	d := devs[0]
	if d.IP != "192.168.1.10" || d.MAC != "aa:bb:cc:dd:ee:10" {
		t.Fatalf("unexpected device: %+v", d)
	}
	if !d.FirstSeen.Equal(t0) || !d.LastSeen.Equal(t0) {
		t.Fatalf("expected FirstSeen==LastSeen==t0, got first=%v last=%v", d.FirstSeen, d.LastSeen)
	}
	if d.Hostname != "" {
		t.Fatalf("expected empty hostname, got %q", d.Hostname)
	}

	// Second cycle later: DHCP lease enriches with hostname; LastSeen advances
	// but FirstSeen is preserved.
	clk.Advance(5 * time.Minute)
	inv.merge(
		[]arpEntry{{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:10"}},
		[]dhcpLease{{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:10", Hostname: "roshan-laptop"}},
	)

	devs = inv.Devices()
	if len(devs) != 1 {
		t.Fatalf("expected still 1 device, got %d", len(devs))
	}
	d = devs[0]
	if d.Hostname != "roshan-laptop" {
		t.Errorf("expected hostname enriched to roshan-laptop, got %q", d.Hostname)
	}
	if !d.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen should be preserved as t0, got %v", d.FirstSeen)
	}
	wantLast := t0.Add(5 * time.Minute)
	if !d.LastSeen.Equal(wantLast) {
		t.Errorf("LastSeen = %v, want %v", d.LastSeen, wantLast)
	}
}

func TestMerge_MultipleDevicesSortedAndCopied(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_750_000_000, 0).UTC()}
	inv := New(Config{Enabled: true}, clk)

	inv.merge([]arpEntry{
		{IP: "192.168.1.30", MAC: "aa:bb:cc:dd:ee:30"},
		{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:10"},
		{IP: "192.168.1.20", MAC: "aa:bb:cc:dd:ee:20"},
	}, nil)

	devs := inv.Devices()
	if len(devs) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(devs))
	}
	wantOrder := []string{"192.168.1.10", "192.168.1.20", "192.168.1.30"}
	for i, ip := range wantOrder {
		if devs[i].IP != ip {
			t.Errorf("devices not sorted by IP: pos %d = %s, want %s", i, devs[i].IP, ip)
		}
	}

	// Mutating the returned snapshot must not affect internal state.
	devs[0].Hostname = "mutated"
	if again := inv.Devices(); again[0].Hostname != "" {
		t.Errorf("Devices() returned a shared reference; internal state was mutated")
	}
}

func TestDHCPOnlyDevice(t *testing.T) {
	// A device present in DHCP but not (yet) in ARP should still be recorded.
	clk := &fakeClock{t: time.Unix(1_750_000_000, 0).UTC()}
	inv := New(Config{Enabled: true}, clk)

	inv.merge(nil, []dhcpLease{{IP: "192.168.1.200", MAC: "aa:bb:cc:dd:ee:c8", Hostname: "iot-bulb"}})

	devs := inv.Devices()
	if len(devs) != 1 {
		t.Fatalf("expected 1 device from DHCP-only, got %d", len(devs))
	}
	if devs[0].Hostname != "iot-bulb" || devs[0].MAC != "aa:bb:cc:dd:ee:c8" {
		t.Errorf("unexpected DHCP-only device: %+v", devs[0])
	}
}

func TestDisabled_RefreshIsNoOp(t *testing.T) {
	// Disabled inventory must not read any system files. A bogus DHCP path
	// would surface as an error if refresh actually ran; here it must be
	// skipped entirely.
	inv := New(Config{Enabled: false, DHCPLeasesPath: "/nonexistent/does/not/exist"}, &fakeClock{t: time.Now()})

	inv.refresh() // no-op
	inv.Start()   // no-op
	inv.Stop()    // safe even though Start launched nothing

	if got := inv.Devices(); len(got) != 0 {
		t.Errorf("disabled inventory should have no devices, got %d", len(got))
	}
	if inv.Enabled() {
		t.Errorf("Enabled() should report false")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("INVENTORY_ENABLED", "true")
	t.Setenv("DHCP_LEASES_PATH", "/var/lib/misc/dnsmasq.leases")
	cfg := ConfigFromEnv()
	if !cfg.Enabled {
		t.Errorf("expected Enabled=true")
	}
	if cfg.DHCPLeasesPath != "/var/lib/misc/dnsmasq.leases" {
		t.Errorf("unexpected DHCPLeasesPath: %q", cfg.DHCPLeasesPath)
	}
	if cfg.RefreshInterval != DefaultRefreshInterval {
		t.Errorf("expected default refresh interval, got %v", cfg.RefreshInterval)
	}
}

func TestConfigFromEnv_DefaultOff(t *testing.T) {
	t.Setenv("INVENTORY_ENABLED", "")
	t.Setenv("DHCP_LEASES_PATH", "")
	if cfg := ConfigFromEnv(); cfg.Enabled {
		t.Errorf("inventory should default to disabled")
	}
}

func TestLookup(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_750_000_000, 0).UTC()}
	inv := New(Config{Enabled: true}, clk)
	inv.merge(
		[]arpEntry{{IP: "192.168.1.42", MAC: "aa:bb:cc:dd:ee:42"}},
		[]dhcpLease{{IP: "192.168.1.42", MAC: "aa:bb:cc:dd:ee:42", Hostname: "roshan-laptop"}},
	)

	d, ok := inv.Lookup("192.168.1.42")
	if !ok {
		t.Fatal("expected to find the merged device by IP")
	}
	if d.MAC != "aa:bb:cc:dd:ee:42" || d.Hostname != "roshan-laptop" {
		t.Errorf("unexpected device from Lookup: %+v", d)
	}

	if _, ok := inv.Lookup("10.0.0.99"); ok {
		t.Error("Lookup of an unknown IP should report not found")
	}
}
