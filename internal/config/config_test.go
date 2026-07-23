// SPDX-License-Identifier: GPL-3.0-or-later
package config

import (
	"reflect"
	"testing"
)

func TestParseAbusedTLDs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"simple", "zip,mov,top", []string{"zip", "mov", "top"}},
		{"trims spaces", " zip , mov ,top ", []string{"zip", "mov", "top"}},
		{"lowercases", "ZIP,Mov,TOP", []string{"zip", "mov", "top"}},
		{"drops empties", "zip,,mov,", []string{"zip", "mov"}},
		{"single", "xyz", []string{"xyz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAbusedTLDs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAbusedTLDs(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
