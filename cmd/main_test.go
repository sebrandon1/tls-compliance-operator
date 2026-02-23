/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"strings"
	"testing"
)

func TestResolveEnvConfig_EnvOverridesDefault(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("scan-interval", "1h", "")
	_ = fs.Parse([]string{}) // no flags set

	env := map[string]string{
		"TLS_COMPLIANCE_SCAN_INTERVAL": "30m",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	msgs := resolveEnvConfig(fs, lookup)

	val := fs.Lookup("scan-interval").Value.String()
	if val != "30m" {
		t.Errorf("expected scan-interval=30m, got %s", val)
	}

	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "set via env") && strings.Contains(msg, "TLS_COMPLIANCE_SCAN_INTERVAL") {
			found = true
		}
	}
	if !found {
		t.Error("expected log message indicating env var was applied")
	}
}

func TestResolveEnvConfig_CLIFlagTakesPrecedence(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("scan-interval", "1h", "")
	_ = fs.Parse([]string{"--scan-interval=15m"}) // explicitly set

	env := map[string]string{
		"TLS_COMPLIANCE_SCAN_INTERVAL": "30m",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	msgs := resolveEnvConfig(fs, lookup)

	val := fs.Lookup("scan-interval").Value.String()
	if val != "15m" {
		t.Errorf("expected scan-interval=15m (from CLI), got %s", val)
	}

	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "set via CLI flag") {
			found = true
		}
	}
	if !found {
		t.Error("expected log message indicating CLI flag was used")
	}
}

func TestResolveEnvConfig_DefaultWhenNoEnv(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("scan-interval", "1h", "")
	_ = fs.Parse([]string{})

	lookup := func(key string) (string, bool) {
		return "", false
	}

	msgs := resolveEnvConfig(fs, lookup)

	val := fs.Lookup("scan-interval").Value.String()
	if val != "1h" {
		t.Errorf("expected scan-interval=1h (default), got %s", val)
	}

	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "using default") {
			found = true
		}
	}
	if !found {
		t.Error("expected log message indicating default was used")
	}
}

func TestResolveEnvConfig_InvalidEnvValueIgnored(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Int("workers", 5, "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_WORKERS": "999",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	msgs := resolveEnvConfig(fs, lookup)

	val := fs.Lookup("workers").Value.String()
	if val != "5" {
		t.Errorf("expected workers=5 (default, invalid env ignored), got %s", val)
	}

	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "ignoring invalid") {
			found = true
		}
	}
	if !found {
		t.Error("expected log message about ignoring invalid value")
	}
}

func TestResolveEnvConfig_InvalidDurationIgnored(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("scan-interval", "1h", "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_SCAN_INTERVAL": "not-a-duration",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	msgs := resolveEnvConfig(fs, lookup)

	val := fs.Lookup("scan-interval").Value.String()
	if val != "1h" {
		t.Errorf("expected scan-interval=1h (default), got %s", val)
	}

	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "ignoring invalid") {
			found = true
		}
	}
	if !found {
		t.Error("expected log message about ignoring invalid value")
	}
}

func TestResolveEnvConfig_AllMappings(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("scan-interval", "1h", "")
	fs.String("tls-check-timeout", "5s", "")
	fs.Float64("rate-limit", 10.0, "")
	fs.Int("workers", 5, "")
	fs.String("exclude-namespaces", "", "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_SCAN_INTERVAL":      "2h",
		"TLS_COMPLIANCE_CHECK_TIMEOUT":      "10s",
		"TLS_COMPLIANCE_RATE_LIMIT":         "20",
		"TLS_COMPLIANCE_WORKERS":            "8",
		"TLS_COMPLIANCE_EXCLUDE_NAMESPACES": "kube-system,kube-public",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	_ = resolveEnvConfig(fs, lookup)

	tests := []struct {
		flag     string
		expected string
	}{
		{"scan-interval", "2h"},
		{"tls-check-timeout", "10s"},
		{"rate-limit", "20"},
		{"workers", "8"},
		{"exclude-namespaces", "kube-system,kube-public"},
	}

	for _, tc := range tests {
		val := fs.Lookup(tc.flag).Value.String()
		if val != tc.expected {
			t.Errorf("expected %s=%s, got %s", tc.flag, tc.expected, val)
		}
	}
}

func TestValidateEnvValue(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		value   string
		wantErr bool
	}{
		{"valid duration", "scan-interval", "30m", false},
		{"invalid duration", "scan-interval", "abc", true},
		{"valid timeout", "tls-check-timeout", "10s", false},
		{"invalid timeout", "tls-check-timeout", "xyz", true},
		{"valid rate-limit", "rate-limit", "15.5", false},
		{"invalid rate-limit", "rate-limit", "abc", true},
		{"valid workers", "workers", "10", false},
		{"workers too low", "workers", "0", true},
		{"workers too high", "workers", "51", true},
		{"invalid workers", "workers", "abc", true},
		{"unknown flag passes", "exclude-namespaces", "anything", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEnvValue(tc.flag, tc.value)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateEnvValue(%s, %s) error = %v, wantErr = %v", tc.flag, tc.value, err, tc.wantErr)
			}
		})
	}
}
