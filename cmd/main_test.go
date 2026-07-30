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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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
		{"valid output-format csv", "output-format", "csv", false},
		{"valid output-format junit", "output-format", "junit", false},
		{"invalid output-format", "output-format", "xml", true},
		{"valid retention-days", "report-retention-days", "30", false},
		{"retention-days zero", "report-retention-days", "0", false},
		{"retention-days negative", "report-retention-days", "-1", true},
		{"retention-days non-integer", "report-retention-days", "abc", true},
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
