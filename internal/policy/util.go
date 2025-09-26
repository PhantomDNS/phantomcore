package policy

import "strings"

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.ToLower(d)
	// strip trailing dot if present
	if len(d) > 0 && d[len(d)-1] == '.' {
		d = d[:len(d)-1]
	}
	return d
}
