// SPDX-License-Identifier: GPL-3.0-or-later

package alert

import "github.com/lopster568/phantomDNS/internal/inventory"

// InventoryResolver adapts the passive LAN inventory to a DeviceResolver so
// that infected-device alerts can be enriched with a device's MAC and
// hostname, keyed by client IP.
type InventoryResolver struct {
	inv *inventory.Inventory
}

// NewInventoryResolver wraps an inventory as a DeviceResolver. A nil inventory
// is tolerated and simply resolves every IP as unknown.
func NewInventoryResolver(inv *inventory.Inventory) *InventoryResolver {
	return &InventoryResolver{inv: inv}
}

// Lookup implements DeviceResolver by consulting the inventory's IP -> Device
// map. It returns false when the inventory is absent or the IP is unknown.
func (r *InventoryResolver) Lookup(ip string) (DeviceInfo, bool) {
	if r == nil || r.inv == nil {
		return DeviceInfo{}, false
	}
	d, ok := r.inv.Lookup(ip)
	if !ok {
		return DeviceInfo{}, false
	}
	return DeviceInfo{IP: d.IP, MAC: d.MAC, Hostname: d.Hostname}, true
}
