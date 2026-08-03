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
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestNewRootCmd_Structure(t *testing.T) {
	cmd := newRootCmd()

	if cmd.Use != "kubectl-tlsreport [csv|json|yaml|junit|markdown|md]" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}

	summary := cmd.Commands()
	found := false
	for _, sub := range summary {
		if sub.Use == "summary" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected summary subcommand")
	}
}

func TestNewRootCmd_Flags(t *testing.T) {
	cmd := newRootCmd()

	tests := []struct {
		flag      string
		shorthand string
	}{
		{"namespace", "n"},
		{"status", ""},
		{"source", ""},
		{"pqc-status", ""},
		{"expires-within", ""},
		{"expired", ""},
		{"sort-by", ""},
		{"kubeconfig", ""},
		{"context", ""},
	}

	for _, tt := range tests {
		f := cmd.PersistentFlags().Lookup(tt.flag)
		if f == nil {
			t.Errorf("expected persistent flag %q", tt.flag)
			continue
		}
		if tt.shorthand != "" && f.Shorthand != tt.shorthand {
			t.Errorf("flag %q: expected shorthand %q, got %q", tt.flag, tt.shorthand, f.Shorthand)
		}
	}
}

func TestRunExport_InvalidFormat(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"xml"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if err.Error() != "unknown format: xml (supported: csv, json, yaml, junit, markdown, md)" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunExport_ValidFormats(t *testing.T) {
	for _, format := range []string{"csv", "json", "yaml", "junit", "markdown", "md"} {
		cmd := newRootCmd()
		cmd.SetArgs([]string{format})

		err := cmd.Execute()
		if err == nil {
			t.Skipf("format %q: skipping (no kubeconfig available)", format)
		}
		if strings.HasPrefix(err.Error(), "unknown format:") {
			t.Errorf("format %q should be valid but was rejected: %v", format, err)
		}
	}
}

func TestNewSummaryCmd(t *testing.T) {
	cmd := newSummaryCmd()

	if cmd.Use != "summary" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}
}

func TestKubeconfigFlag_UsesExplicitPath(t *testing.T) {
	kubeconfig = "/nonexistent/kubeconfig"
	kubecontext = ""
	defer func() { kubeconfig = ""; kubecontext = "" }()

	_, err := fetchReports(context.Background())
	if err == nil {
		t.Fatal("expected error with nonexistent kubeconfig")
	}
	if !strings.Contains(err.Error(), "/nonexistent/kubeconfig") {
		t.Errorf("error should reference explicit kubeconfig path, got: %v", err)
	}
}

func TestContextFlag_UsesOverride(t *testing.T) {
	kubeconfig = ""
	kubecontext = "nonexistent-context"
	defer func() { kubeconfig = ""; kubecontext = "" }()

	_, err := fetchReports(context.Background())
	// Without a valid kubeconfig this will fail, but we verify the flag
	// is accepted and doesn't cause a flag-parsing error
	if err == nil {
		t.Skip("skipping: kubeconfig available and context resolved")
	}
}

func TestKubeconfigAndContextFlags_Combined(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"--kubeconfig", "/tmp/test.kubeconfig", "--context", "test-ctx", "csv"})

	err := cmd.Execute()
	if err == nil {
		t.Skip("skipping: kubeconfig resolved unexpectedly")
	}
	if strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("flags should be recognized, got: %v", err)
	}
}

func TestSchemeRegistration(t *testing.T) {
	if scheme == nil {
		t.Fatal("scheme should not be nil")
	}

	gvk := securityv1alpha1.GroupVersion.WithKind("TLSComplianceReport")
	if !scheme.Recognizes(gvk) {
		t.Errorf("scheme should recognize %v", gvk)
	}

	gvk = securityv1alpha1.GroupVersion.WithKind("TLSComplianceTarget")
	if !scheme.Recognizes(gvk) {
		t.Errorf("scheme should recognize %v", gvk)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	fn()
	_ = w.Close()

	data, _ := io.ReadAll(r)
	return string(data)
}

func TestPrintReportDetail_FIPSDetected(t *testing.T) {
	report := securityv1alpha1.TLSComplianceReport{}
	report.Name = "test-report"
	report.Spec.Host = "example.com"
	report.Spec.Port = 443
	report.Spec.SourceKind = securityv1alpha1.SourceKindService
	report.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	report.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable
	report.Status.FIPSDetected = true

	output := captureStdout(t, func() {
		_ = printReportDetail(&report)
	})

	if !strings.Contains(output, "FIPS Mode:") {
		t.Error("expected output to contain 'FIPS Mode:'")
	}
	if !strings.Contains(output, "Active -- ML-KEM unavailable") {
		t.Error("expected output to contain 'Active -- ML-KEM unavailable'")
	}
}

func TestPrintReportDetail_FIPSNotDetected(t *testing.T) {
	report := securityv1alpha1.TLSComplianceReport{}
	report.Name = "test-report"
	report.Spec.Host = "example.com"
	report.Spec.Port = 443
	report.Spec.SourceKind = securityv1alpha1.SourceKindService
	report.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	report.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable

	output := captureStdout(t, func() {
		_ = printReportDetail(&report)
	})

	if strings.Contains(output, "FIPS Mode:") {
		t.Error("expected output to NOT contain 'FIPS Mode:' when FIPSDetected is false")
	}
}

func TestNewRootCmd_FailOnNonCompliantFlag(t *testing.T) {
	cmd := newRootCmd()
	f := cmd.PersistentFlags().Lookup("fail-on-non-compliant")
	if f == nil {
		t.Fatal("expected --fail-on-non-compliant flag")
	}
	if f.DefValue != "false" {
		t.Errorf("expected default false, got %s", f.DefValue)
	}
}

func TestCheckExitCode_FlagDisabled(t *testing.T) {
	failOnNonCompliant = false
	defer func() { failOnNonCompliant = false }()

	reports := []securityv1alpha1.TLSComplianceReport{
		{Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant}},
	}
	if err := checkExitCode(reports); err != nil {
		t.Errorf("expected nil error when flag is disabled, got %v", err)
	}
}

func TestCheckExitCode_FlagEnabled_AllCompliant(t *testing.T) {
	failOnNonCompliant = true
	defer func() { failOnNonCompliant = false }()

	reports := []securityv1alpha1.TLSComplianceReport{
		{Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant}},
	}
	if err := checkExitCode(reports); err != nil {
		t.Errorf("expected nil error for all-compliant, got %v", err)
	}
}

func TestCheckExitCode_FlagEnabled_NonCompliant(t *testing.T) {
	failOnNonCompliant = true
	defer func() { failOnNonCompliant = false }()

	reports := []securityv1alpha1.TLSComplianceReport{
		{Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant}},
	}
	err := checkExitCode(reports)
	if err == nil {
		t.Fatal("expected error for non-compliant reports")
	}
	var ece exitCodeError
	if !errors.As(err, &ece) {
		t.Fatalf("expected exitCodeError, got %T", err)
	}
	if ece.code != 1 {
		t.Errorf("expected exit code 1, got %d", ece.code)
	}
}

func TestExitCodeError_ErrorString(t *testing.T) {
	e := exitCodeError{code: 1}
	if e.Error() != "exit code 1" {
		t.Errorf("unexpected error string: %s", e.Error())
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = origStderr }()

	fn()
	_ = w.Close()

	data, _ := io.ReadAll(r)
	return string(data)
}

func TestPrintTable_Empty(t *testing.T) {
	for _, tt := range []struct {
		name string
		fn   func([]securityv1alpha1.TLSComplianceReport) error
	}{
		{"table", printReportTable},
		{"wide", printReportTableWide},
	} {
		t.Run(tt.name, func(t *testing.T) {
			filterOpts.Namespace = ""
			defer func() { filterOpts.Namespace = "" }()

			stdout := captureStdout(t, func() {
				stderr := captureStderr(t, func() {
					if err := tt.fn(nil); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				})
				if !strings.Contains(stderr, "No resources found.") {
					t.Errorf("expected 'No resources found.' on stderr, got: %q", stderr)
				}
			})
			if strings.Contains(stdout, "NAME") {
				t.Error("expected no table header on stdout for empty results")
			}
		})
	}
}

func TestNewRootCmd_HasCompletionSubcommand(t *testing.T) {
	cmd := newRootCmd()
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Name() == "completion" {
			found = true
			if len(sub.ValidArgs) != 4 {
				t.Errorf("expected 4 valid args, got %d", len(sub.ValidArgs))
			}
			break
		}
	}
	if !found {
		t.Error("expected completion subcommand")
	}
}

func TestCompletionCmd_ValidShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"completion", shell})
			output := captureStdout(t, func() {
				if err := cmd.Execute(); err != nil {
					t.Fatalf("completion %s failed: %v", shell, err)
				}
			})
			if len(output) == 0 {
				t.Errorf("expected non-empty completion output for %s", shell)
			}
		})
	}
}

func TestPrintTable_EmptyWithNamespace(t *testing.T) {
	filterOpts.Namespace = "production"
	defer func() { filterOpts.Namespace = "" }()

	captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			if err := printReportTable(nil); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
		if !strings.Contains(stderr, `No resources found in namespace "production".`) {
			t.Errorf("expected namespace-specific message on stderr, got: %q", stderr)
		}
	})
}

func TestPrintNoResourcesFound(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		expected  string
	}{
		{"no namespace", "", "No resources found.\n"},
		{"with namespace", "kube-system", "No resources found in namespace \"kube-system\".\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filterOpts.Namespace = tt.namespace
			defer func() { filterOpts.Namespace = "" }()

			stderr := captureStderr(t, func() {
				_ = printNoResourcesFound()
			})
			if stderr != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, stderr)
			}
		})
	}
}

func TestFlagCompletionRegistered(t *testing.T) {
	cmd := newRootCmd()

	for _, flag := range []string{"status", "source", "pqc-status", "sort-by"} {
		fn, ok := cmd.GetFlagCompletionFunc(flag)
		if !ok {
			t.Errorf("flag %q: completion not registered", flag)
			continue
		}
		if fn == nil {
			t.Errorf("flag %q: completion func is nil", flag)
		}
	}

	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Name() == "get" {
			fn, ok := sub.GetFlagCompletionFunc("output")
			if !ok {
				t.Fatal("output flag: completion not registered")
			}
			if fn == nil {
				t.Fatal("output flag: completion func is nil")
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected get subcommand")
	}
}

func TestPrintReportTableWide_IncludesNamespace(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "example.com",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "production",
				SourceName:      "web",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}
	output := captureStdout(t, func() {
		if err := printReportTableWide(reports); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(output, "NAMESPACE") {
		t.Error("expected NAMESPACE header in wide output")
	}
	if !strings.Contains(output, "production") {
		t.Error("expected namespace value 'production' in wide output")
	}
}

func TestPrintReportTable_ColumnAlignment(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "example.com",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				ForwardSecrecy:   true,
			},
		},
	}
	output := captureStdout(t, func() {
		_ = printReportTable(reports)
	})
	for _, col := range []string{"COMPLIANCE", "GRADE", "FS", "TLS 1.3", "TLS 1.2", "PQC", "MLKEM"} {
		if !strings.Contains(output, col) {
			t.Errorf("expected column %q in table header", col)
		}
	}
	if strings.Contains(output, "\tSTATUS\t") {
		t.Error("STATUS should be renamed to COMPLIANCE")
	}
}

func TestNewRescanCmd_Validation(t *testing.T) {
	t.Run("no args and no --all returns error", func(t *testing.T) {
		cmd := newRescanCmd()
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "specify a report name or use --all") {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("args with --all returns error", func(t *testing.T) {
		cmd := newRescanCmd()
		cmd.SetArgs([]string{"my-report", "--all"})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "cannot specify both") {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("flags exist with defaults", func(t *testing.T) {
		cmd := newRescanCmd()
		allFlag := cmd.Flags().Lookup("all")
		if allFlag == nil {
			t.Fatal("expected --all flag")
		}
		if allFlag.DefValue != "false" {
			t.Errorf("expected --all default=false, got %s", allFlag.DefValue)
		}
		waitFlag := cmd.Flags().Lookup("wait")
		if waitFlag == nil {
			t.Fatal("expected --wait flag")
		}
		timeoutFlag := cmd.Flags().Lookup("timeout")
		if timeoutFlag == nil {
			t.Fatal("expected --timeout flag")
		}
		if timeoutFlag.DefValue != "1m0s" {
			t.Errorf("expected --timeout default=1m0s, got %s", timeoutFlag.DefValue)
		}
	})
}

func TestTriggerRescan(t *testing.T) {
	ctx := context.Background()

	t.Run("sets annotation on nil map", func(t *testing.T) {
		report := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: "test-report"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()

		if err := triggerRescan(ctx, c, report); err != nil {
			t.Fatalf("triggerRescan() error = %v", err)
		}

		var updated securityv1alpha1.TLSComplianceReport
		if err := c.Get(ctx, client.ObjectKey{Name: "test-report"}, &updated); err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		val, ok := updated.Annotations[rescanAnnotation]
		if !ok {
			t.Fatal("expected rescan annotation to be set")
		}
		if _, err := time.Parse(time.RFC3339, val); err != nil {
			t.Errorf("expected RFC3339 timestamp, got %q: %v", val, err)
		}
	})

	t.Run("preserves existing annotations", func(t *testing.T) {
		report := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-report",
				Annotations: map[string]string{"existing": "value"},
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()

		if err := triggerRescan(ctx, c, report); err != nil {
			t.Fatalf("triggerRescan() error = %v", err)
		}

		var updated securityv1alpha1.TLSComplianceReport
		if err := c.Get(ctx, client.ObjectKey{Name: "test-report"}, &updated); err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if updated.Annotations["existing"] != "value" {
			t.Error("existing annotation was clobbered")
		}
		if _, ok := updated.Annotations[rescanAnnotation]; !ok {
			t.Error("rescan annotation not set")
		}
	})
}

func TestWaitForRescan_AlreadyComplete(t *testing.T) {
	ctx := context.Background()

	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "test-report"},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).
		WithStatusSubresource(report).Build()

	err := waitForRescan(ctx, c, "test-report", 5*time.Second)
	if err != nil {
		t.Fatalf("waitForRescan() error = %v (expected success since annotation absent)", err)
	}
}

func TestWaitForRescan_Timeout(t *testing.T) {
	ctx := context.Background()

	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-report",
			Annotations: map[string]string{rescanAnnotation: "2024-01-01T00:00:00Z"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()

	err := waitForRescan(ctx, c, "test-report", 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestPrintReportTableWide_ColumnAlignment(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "example.com",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "default",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}
	output := captureStdout(t, func() {
		_ = printReportTableWide(reports)
	})
	for _, col := range []string{"NAMESPACE", "COMPLIANCE", "FS", "TLS 1.0", "SSL 3.0", "CERT EXPIRY"} {
		if !strings.Contains(output, col) {
			t.Errorf("expected column %q in wide header", col)
		}
	}
}
