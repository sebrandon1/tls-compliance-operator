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
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
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
		{"negative rate-limit", "rate-limit", "-5", true},
		{"zero rate-limit", "rate-limit", "0", true},
		{"valid workers", "workers", "10", false},
		{"workers too low", "workers", "0", true},
		{"workers too high", "workers", "51", true},
		{"invalid workers", "workers", "abc", true},
		{"unknown flag passes", "exclude-namespaces", "anything", false},
		{"valid extra-tls-ports", "extra-tls-ports", "9443,6380,5671", false},
		{"invalid extra-tls-ports non-number", "extra-tls-ports", "abc", true},
		{"invalid extra-tls-ports out of range", "extra-tls-ports", "70000", true},
		{"invalid extra-tls-ports zero", "extra-tls-ports", "0", true},
		{"valid log-format text", "log-format", "text", false},
		{"valid log-format json", "log-format", "json", false},
		{"invalid log-format", "log-format", "xml", true},
		{"valid run-once true", "run-once", "true", false},
		{"valid run-once false", "run-once", "false", false},
		{"valid run-once 1", "run-once", "1", false},
		{"valid run-once 0", "run-once", "0", false},
		{"invalid run-once", "run-once", "maybe", true},
		{"valid scan-all-ports true", "scan-all-ports", "true", false},
		{"valid scan-all-ports false", "scan-all-ports", "false", false},
		{"valid scan-all-ports 1", "scan-all-ports", "1", false},
		{"invalid scan-all-ports", "scan-all-ports", "maybe", true},
		{"valid enumerate-ciphers true", "enumerate-ciphers", "true", false},
		{"valid enumerate-ciphers false", "enumerate-ciphers", "false", false},
		{"invalid enumerate-ciphers", "enumerate-ciphers", "maybe", true},
		{"valid metrics-per-endpoint true", "metrics-per-endpoint", "true", false},
		{"valid metrics-per-endpoint false", "metrics-per-endpoint", "false", false},
		{"invalid metrics-per-endpoint", "metrics-per-endpoint", "maybe", true},
		{"valid output-format csv", "output-format", "csv", false},
		{"valid output-format junit", "output-format", "junit", false},
		{"valid output-format html", "output-format", "html", false},
		{"valid output-format sarif", "output-format", "sarif", false},
		{"invalid output-format", "output-format", "xml", true},
		{"valid retention-days", "report-retention-days", "30", false},
		{"retention-days zero", "report-retention-days", "0", false},
		{"retention-days negative", "report-retention-days", "-1", true},
		{"retention-days non-integer", "report-retention-days", "abc", true},
		{"valid max-history-entries", "max-history-entries", "10", false},
		{"max-history-entries zero", "max-history-entries", "0", true},
		{"max-history-entries too high", "max-history-entries", "101", true},
		{"max-history-entries non-integer", "max-history-entries", "abc", true},
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

func TestParsePortList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{"single port", "9443", 1, false},
		{"multiple ports", "9443,6380,5671", 3, false},
		{"spaces trimmed", " 9443 , 6380 ", 2, false},
		{"empty string", "", 0, false},
		{"trailing comma", "9443,", 1, false},
		{"non-number", "abc", 0, true},
		{"port zero", "0", 0, true},
		{"port too high", "65536", 0, true},
		{"negative port", "-1", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ports, err := parsePortList(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("parsePortList(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
				return
			}
			if !tc.wantErr && len(ports) != tc.want {
				t.Errorf("parsePortList(%q) returned %d ports, want %d", tc.input, len(ports), tc.want)
			}
		})
	}
}

func TestResolveEnvConfig_ExtraTLSPorts(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("extra-tls-ports", "", "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_EXTRA_TLS_PORTS": "9443,6380",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	_ = resolveEnvConfig(fs, lookup)

	val := fs.Lookup("extra-tls-ports").Value.String()
	if val != "9443,6380" {
		t.Errorf("expected extra-tls-ports=9443,6380, got %s", val)
	}
}

func TestResolveEnvConfig_ScanAllPorts(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("scan-all-ports", false, "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_SCAN_ALL_PORTS": "true",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	_ = resolveEnvConfig(fs, lookup)

	val := fs.Lookup("scan-all-ports").Value.String()
	if val != "true" {
		t.Errorf("expected scan-all-ports=true, got %s", val)
	}
}

func TestResolveEnvConfig_LogFormat(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("log-format", "text", "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_LOG_FORMAT": "json",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	_ = resolveEnvConfig(fs, lookup)

	val := fs.Lookup("log-format").Value.String()
	if val != "json" {
		t.Errorf("expected log-format=json, got %s", val)
	}
}

func TestWriteRunOnceOutput_CSV(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "test.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "results.csv")
	cfg := &operatorConfig{outputFormat: "csv", outputFile: tmpFile}

	if err := writeRunOnceOutput(reports, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "test.example") {
		t.Error("expected output file to contain host")
	}
}

func TestWriteRunOnceOutput_JUnit(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "junit.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "results.xml")
	cfg := &operatorConfig{outputFormat: "junit", outputFile: tmpFile}

	if err := writeRunOnceOutput(reports, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "junit.example") {
		t.Error("expected JUnit output to contain host")
	}
}

func TestWriteRunOnceOutput_Stdout(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "stdout.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	cfg := &operatorConfig{outputFormat: "json"}
	if err := writeRunOnceOutput(reports, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteRunOnceOutput_InvalidFormat(t *testing.T) {
	cfg := &operatorConfig{outputFormat: "xml"}
	err := writeRunOnceOutput(nil, cfg)
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestWriteRunOnceOutput_BadPath(t *testing.T) {
	cfg := &operatorConfig{outputFormat: "csv", outputFile: "/nonexistent/dir/file.csv"}
	err := writeRunOnceOutput(nil, cfg)
	if err == nil {
		t.Fatal("expected error for bad file path")
	}
}

func TestResolveEnvConfig_ReportRetentionDays(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Int("report-retention-days", 0, "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_REPORT_RETENTION_DAYS": "90",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	msgs := resolveEnvConfig(fs, lookup)

	val := fs.Lookup("report-retention-days").Value.String()
	if val != "90" {
		t.Errorf("expected report-retention-days=90, got %s", val)
	}

	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "set via env") && strings.Contains(msg, "TLS_COMPLIANCE_REPORT_RETENTION_DAYS") {
			found = true
		}
	}
	if !found {
		t.Error("expected log message indicating env var was applied")
	}
}

func TestResolveEnvConfig_EnumerateCiphers(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("enumerate-ciphers", true, "")
	_ = fs.Parse([]string{})

	lookup := func(key string) (string, bool) {
		if key == "TLS_COMPLIANCE_ENUMERATE_CIPHERS" {
			return "false", true
		}
		return "", false
	}

	resolveEnvConfig(fs, lookup)
	if fs.Lookup("enumerate-ciphers").Value.String() != "false" {
		t.Errorf("expected enumerate-ciphers=false, got %s", fs.Lookup("enumerate-ciphers").Value.String())
	}
}

func TestResolveEnvConfig_MetricsPerEndpoint(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("metrics-per-endpoint", false, "")
	_ = fs.Parse([]string{})

	lookup := func(key string) (string, bool) {
		if key == "TLS_COMPLIANCE_METRICS_PER_ENDPOINT" {
			return "true", true
		}
		return "", false
	}

	resolveEnvConfig(fs, lookup)
	if fs.Lookup("metrics-per-endpoint").Value.String() != "true" {
		t.Errorf("expected metrics-per-endpoint=true from env, got %s", fs.Lookup("metrics-per-endpoint").Value.String())
	}
}

func TestResolveEnvConfig_NamespaceRateLimits(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("namespace-rate-limits", "", "")
	_ = fs.Parse([]string{})

	lookup := func(key string) (string, bool) {
		if key == "TLS_COMPLIANCE_NAMESPACE_RATE_LIMITS" {
			return "production=2.0,staging=10.0", true
		}
		return "", false
	}

	resolveEnvConfig(fs, lookup)
	if fs.Lookup("namespace-rate-limits").Value.String() != "production=2.0,staging=10.0" {
		t.Errorf("expected namespace-rate-limits=production=2.0,staging=10.0, got %s", fs.Lookup("namespace-rate-limits").Value.String())
	}
}

func TestCheckConfig(t *testing.T) {
	validCfg := func() *operatorConfig {
		return &operatorConfig{
			workers:           5,
			maxRetries:        3,
			rateLimit:         10.0,
			rateBurst:         20,
			scanInterval:      1 * time.Hour,
			cleanupInterval:   5 * time.Minute,
			tlsCheckTimeout:   5 * time.Second,
			maxHistoryEntries: 10,
		}
	}

	t.Run("valid config", func(t *testing.T) {
		warnings, err := checkConfig(validCfg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("unexpected warnings: %v", warnings)
		}
	})

	t.Run("rate-limit zero", func(t *testing.T) {
		cfg := validCfg()
		cfg.rateLimit = 0
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "rate-limit") {
			t.Errorf("expected rate-limit error, got: %v", err)
		}
	})

	t.Run("rate-limit negative", func(t *testing.T) {
		cfg := validCfg()
		cfg.rateLimit = -1
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "rate-limit") {
			t.Errorf("expected rate-limit error, got: %v", err)
		}
	})

	t.Run("rate-burst too low", func(t *testing.T) {
		cfg := validCfg()
		cfg.rateBurst = 0
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "rate-burst") {
			t.Errorf("expected rate-burst error, got: %v", err)
		}
	})

	t.Run("rate-burst too high", func(t *testing.T) {
		cfg := validCfg()
		cfg.rateBurst = 1001
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "rate-burst") {
			t.Errorf("expected rate-burst error, got: %v", err)
		}
	})

	t.Run("client-cert without client-key", func(t *testing.T) {
		cfg := validCfg()
		cfg.clientCertPath = "/path/to/cert.pem"
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "client-key") {
			t.Errorf("expected client-key error, got: %v", err)
		}
	})

	t.Run("client-key without client-cert", func(t *testing.T) {
		cfg := validCfg()
		cfg.clientKeyPath = "/path/to/key.pem"
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "client-cert") {
			t.Errorf("expected client-cert error, got: %v", err)
		}
	})

	t.Run("both client-cert and client-key is valid", func(t *testing.T) {
		cfg := validCfg()
		cfg.clientCertPath = "/path/to/cert.pem"
		cfg.clientKeyPath = "/path/to/key.pem"
		_, err := checkConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("include and exclude namespaces warns", func(t *testing.T) {
		cfg := validCfg()
		cfg.includeNamespaces = "ns1"
		cfg.excludeNamespaces = "ns2"
		warnings, err := checkConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(warnings) == 0 {
			t.Error("expected warning about include+exclude namespaces")
		}
	})

	t.Run("workers much higher than rate-limit warns", func(t *testing.T) {
		cfg := validCfg()
		cfg.workers = 50
		cfg.rateLimit = 1.0
		warnings, err := checkConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		found := false
		for _, w := range warnings {
			if strings.Contains(w, "workers") {
				found = true
			}
		}
		if !found {
			t.Error("expected warning about workers vs rate-limit")
		}
	})

	t.Run("workers proportional to rate-limit no warning", func(t *testing.T) {
		cfg := validCfg()
		cfg.workers = 5
		cfg.rateLimit = 10.0
		warnings, err := checkConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "workers") {
				t.Errorf("unexpected workers warning: %s", w)
			}
		}
	})
}

func TestCheckConfig_ReportRetentionDays(t *testing.T) {
	validCfg := func() *operatorConfig {
		return &operatorConfig{
			workers:           5,
			maxRetries:        3,
			rateLimit:         10.0,
			rateBurst:         20,
			scanInterval:      1 * time.Hour,
			cleanupInterval:   5 * time.Minute,
			tlsCheckTimeout:   5 * time.Second,
			maxHistoryEntries: 10,
		}
	}

	t.Run("negative retention days", func(t *testing.T) {
		cfg := validCfg()
		cfg.reportRetentionDays = -1
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "report-retention-days") {
			t.Errorf("expected report-retention-days error, got: %v", err)
		}
	})

	t.Run("retention days too high", func(t *testing.T) {
		cfg := validCfg()
		cfg.reportRetentionDays = 3651
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "report-retention-days") {
			t.Errorf("expected report-retention-days error, got: %v", err)
		}
	})
}

func TestCheckConfig_InvalidMaxHistoryEntries(t *testing.T) {
	validCfg := func() *operatorConfig {
		return &operatorConfig{
			workers:           5,
			maxRetries:        3,
			rateLimit:         10.0,
			rateBurst:         20,
			scanInterval:      1 * time.Hour,
			cleanupInterval:   5 * time.Minute,
			tlsCheckTimeout:   5 * time.Second,
			maxHistoryEntries: 10,
		}
	}

	t.Run("zero max history entries", func(t *testing.T) {
		cfg := validCfg()
		cfg.maxHistoryEntries = 0
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "max-history-entries") {
			t.Errorf("expected max-history-entries error, got: %v", err)
		}
	})

	t.Run("max history entries too high", func(t *testing.T) {
		cfg := validCfg()
		cfg.maxHistoryEntries = 101
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "max-history-entries") {
			t.Errorf("expected max-history-entries error, got: %v", err)
		}
	})
}

func TestCheckConfig_MaxRetries(t *testing.T) {
	validCfg := func() *operatorConfig {
		return &operatorConfig{
			workers:           5,
			maxRetries:        3,
			rateLimit:         10.0,
			rateBurst:         20,
			scanInterval:      1 * time.Hour,
			cleanupInterval:   5 * time.Minute,
			tlsCheckTimeout:   5 * time.Second,
			maxHistoryEntries: 10,
		}
	}

	t.Run("negative retries", func(t *testing.T) {
		cfg := validCfg()
		cfg.maxRetries = -1
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "max-retries") {
			t.Errorf("expected max-retries error, got: %v", err)
		}
	})

	t.Run("retries too high", func(t *testing.T) {
		cfg := validCfg()
		cfg.maxRetries = 11
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "max-retries") {
			t.Errorf("expected max-retries error, got: %v", err)
		}
	})

	t.Run("workers too low", func(t *testing.T) {
		cfg := validCfg()
		cfg.workers = 0
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "workers") {
			t.Errorf("expected workers error, got: %v", err)
		}
	})
}

func TestCheckConfig_OutputFormat(t *testing.T) {
	validCfg := func() *operatorConfig {
		return &operatorConfig{
			workers:           5,
			maxRetries:        3,
			rateLimit:         10.0,
			rateBurst:         20,
			scanInterval:      1 * time.Hour,
			cleanupInterval:   5 * time.Minute,
			tlsCheckTimeout:   5 * time.Second,
			maxHistoryEntries: 10,
		}
	}

	t.Run("invalid format", func(t *testing.T) {
		cfg := validCfg()
		cfg.outputFormat = "xml"
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "output-format") {
			t.Errorf("expected output-format error, got: %v", err)
		}
	})

	t.Run("output-file without output-format", func(t *testing.T) {
		cfg := validCfg()
		cfg.outputFile = "/tmp/out.csv"
		_, err := checkConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "output-file requires") {
			t.Errorf("expected output-file error, got: %v", err)
		}
	})
}

func TestBuildTLSOpts(t *testing.T) {
	t.Run("http2 disabled", func(t *testing.T) {
		cfg := &operatorConfig{enableHTTP2: false}
		opts := buildTLSOpts(cfg)
		if len(opts) != 1 {
			t.Fatalf("expected 1 TLS option, got %d", len(opts))
		}
		tc := &tls.Config{}
		opts[0](tc)
		if len(tc.NextProtos) != 1 || tc.NextProtos[0] != "http/1.1" {
			t.Errorf("expected NextProtos=[http/1.1], got %v", tc.NextProtos)
		}
	})

	t.Run("http2 enabled", func(t *testing.T) {
		cfg := &operatorConfig{enableHTTP2: true}
		opts := buildTLSOpts(cfg)
		if len(opts) != 0 {
			t.Fatalf("expected 0 TLS options, got %d", len(opts))
		}
	})
}

func TestWriteRunOnceOutput_Markdown(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "md.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "results.md")
	cfg := &operatorConfig{outputFormat: "markdown", outputFile: tmpFile}

	if err := writeRunOnceOutput(reports, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "md.example") {
		t.Error("expected output file to contain host")
	}
}

func TestWriteRunOnceOutput_HTML(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "html.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "results.html")
	cfg := &operatorConfig{outputFormat: "html", outputFile: tmpFile}

	if err := writeRunOnceOutput(reports, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "html.example") {
		t.Error("expected output file to contain host")
	}
	if !strings.Contains(string(data), "<html") {
		t.Error("expected HTML document")
	}
}

func TestWriteRunOnceOutput_SARIF(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "sarif.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "results.sarif")
	cfg := &operatorConfig{outputFormat: "sarif", outputFile: tmpFile}

	if err := writeRunOnceOutput(reports, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "sarif.example:443") {
		t.Error("expected output file to contain endpoint")
	}
	if !strings.Contains(string(data), `"version": "2.1.0"`) {
		t.Error("expected SARIF 2.1.0 version")
	}
}

func TestWriteRunOnceOutput_YAML(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "yaml.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "results.yaml")
	cfg := &operatorConfig{outputFormat: "yaml", outputFile: tmpFile}

	if err := writeRunOnceOutput(reports, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "yaml.example") {
		t.Error("expected output file to contain host")
	}
}

func TestValidateEnvValue_AdditionalCases(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		value   string
		wantErr bool
	}{
		{"valid rate-burst", "rate-burst", "50", false},
		{"rate-burst too low", "rate-burst", "0", true},
		{"rate-burst too high", "rate-burst", "1001", true},
		{"valid cert-expiry-warning-days", "cert-expiry-warning-days", "30", false},
		{"cert-expiry-warning-days too low", "cert-expiry-warning-days", "0", true},
		{"cert-expiry-warning-days too high", "cert-expiry-warning-days", "366", true},
		{"valid max-retries", "max-retries", "5", false},
		{"max-retries too high", "max-retries", "11", true},
		{"valid cleanup-interval", "cleanup-interval", "10m", false},
		{"valid profile-refresh-interval", "profile-refresh-interval", "15m", false},
		{"valid retry-backoff", "retry-backoff", "5s", false},
		{"valid max-backoff", "max-backoff", "1m", false},
		{"valid output-format csv", "output-format", "csv", false},
		{"valid output-format yaml", "output-format", "yaml", false},
		{"invalid output-format xml", "output-format", "xml", true},
		{"rate-burst invalid", "rate-burst", "abc", true},
		{"cert-expiry-warning-days invalid", "cert-expiry-warning-days", "abc", true},
		{"max-retries invalid", "max-retries", "abc", true},
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

func TestResolveEnvConfig_MissingFlag(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_SCAN_INTERVAL": "30m",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	msgs := resolveEnvConfig(fs, lookup)
	if len(msgs) == 0 {
		t.Error("expected at least one log message")
	}
}

func TestResolveEnvConfig_SetFailure(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Int("workers", 5, "")
	_ = fs.Parse([]string{})

	env := map[string]string{
		"TLS_COMPLIANCE_WORKERS": "8",
	}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	f := fs.Lookup("workers")
	orig := f.Value
	f.Value = &failSetter{val: orig}

	msgs := resolveEnvConfig(fs, lookup)
	found := false
	for _, msg := range msgs {
		if strings.Contains(msg, "ignoring invalid") {
			found = true
		}
	}
	if !found {
		t.Error("expected log message about ignoring invalid value when Set fails")
	}
}

type failSetter struct {
	val flag.Value
}

func (f *failSetter) String() string { return f.val.String() }
func (f *failSetter) Set(string) error {
	return fmt.Errorf("forced set failure")
}

func TestReadyzCheck_BeforeAndAfterScan(t *testing.T) {
	var scanDone atomic.Bool

	checker := func(_ *http.Request) error {
		if !scanDone.Load() {
			return fmt.Errorf("initial TLS scan not yet completed")
		}
		return nil
	}

	if err := checker(nil); err == nil {
		t.Fatal("readyz should return error before initial scan")
	} else if !strings.Contains(err.Error(), "initial TLS scan not yet completed") {
		t.Errorf("unexpected error message: %v", err)
	}

	scanDone.Store(true)

	if err := checker(nil); err != nil {
		t.Errorf("readyz should return nil after initial scan, got: %v", err)
	}
}
