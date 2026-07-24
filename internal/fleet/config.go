// SPDX-License-Identifier: GPL-3.0-or-later

package fleet

import (
	"os"
	"time"
)

// Config controls the opt-in MSP fleet aggregator. The feature is OFF by
// default: it only activates when explicitly enabled and given a heartbeat
// token that reporting boxes must present.
type Config struct {
	Enabled        bool
	HeartbeatToken string
	StaleAfter     time.Duration
}

// LoadConfig reads fleet configuration from the environment:
//
//	FLEET_ENABLED          "true" to opt in (default off)
//	FLEET_HEARTBEAT_TOKEN  shared token boxes present on /fleet/heartbeat
//	FLEET_STALE_AFTER      Go duration, e.g. "90s" (default 90s)
func LoadConfig() Config {
	c := Config{StaleAfter: DefaultStaleAfter}

	if os.Getenv("FLEET_ENABLED") == "true" {
		c.Enabled = true
	}
	c.HeartbeatToken = os.Getenv("FLEET_HEARTBEAT_TOKEN")
	if v := os.Getenv("FLEET_STALE_AFTER"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.StaleAfter = d
		}
	}
	return c
}
