// SPDX-License-Identifier: GPL-3.0-or-later
package config

import "testing"

func TestParseBoolEnv(t *testing.T) {
	tests := []struct {
		in   string
		def  bool
		want bool
	}{
		{"true", false, true},
		{"1", false, true},
		{"false", true, false},
		{"0", true, false},
		{"", true, true},           // empty is not parseable -> default
		{"nonsense", false, false}, // invalid -> default
		{"nonsense", true, true},   // invalid -> default
	}
	for _, tt := range tests {
		if got := parseBoolEnv(tt.in, tt.def); got != tt.want {
			t.Errorf("parseBoolEnv(%q, %v) = %v, want %v", tt.in, tt.def, got, tt.want)
		}
	}
}
