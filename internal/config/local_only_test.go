// SPDX-License-Identifier: GPL-3.0-or-later
package config

import "testing"

func TestLocalOnly_DefaultIsFalse(t *testing.T) {
	t.Setenv("LOCAL_ONLY", "")
	// With no env override and the default config, custody mode is off.
	DefaultConfig.LocalOnly = false
	if LocalOnly() {
		t.Fatalf("LocalOnly() = true, want false by default")
	}
	if !AssertLocalOnlyRespected("test.feature") {
		t.Fatalf("AssertLocalOnlyRespected() = false, want true when custody mode is off")
	}
}

func TestLocalOnly_EnvOverridesConfig(t *testing.T) {
	// Config says false, env forces custody mode on.
	DefaultConfig.LocalOnly = false

	truthy := []string{"1", "true", "TRUE", "yes", "on"}
	for _, v := range truthy {
		t.Setenv("LOCAL_ONLY", v)
		if !LocalOnly() {
			t.Fatalf("LocalOnly() = false for LOCAL_ONLY=%q, want true", v)
		}
		if AssertLocalOnlyRespected("test.feature") {
			t.Fatalf("AssertLocalOnlyRespected() = true for LOCAL_ONLY=%q, want false", v)
		}
	}

	falsy := []string{"0", "false", "no", "off"}
	for _, v := range falsy {
		t.Setenv("LOCAL_ONLY", v)
		if LocalOnly() {
			t.Fatalf("LocalOnly() = true for LOCAL_ONLY=%q, want false", v)
		}
	}
}

func TestLocalOnly_ReflectsConfigWhenEnvUnset(t *testing.T) {
	t.Setenv("LOCAL_ONLY", "") // present-but-empty => unrecognized => fall back to config
	DefaultConfig.LocalOnly = true
	defer func() { DefaultConfig.LocalOnly = false }()
	if !LocalOnly() {
		t.Fatalf("LocalOnly() = false, want true when config LocalOnly is set and env is empty")
	}
}

func TestLocalOnly_UnrecognizedEnvFallsBackToConfig(t *testing.T) {
	t.Setenv("LOCAL_ONLY", "maybe")
	DefaultConfig.LocalOnly = true
	defer func() { DefaultConfig.LocalOnly = false }()
	if !LocalOnly() {
		t.Fatalf("LocalOnly() = false for unrecognized env, want fallback to config value true")
	}
}
