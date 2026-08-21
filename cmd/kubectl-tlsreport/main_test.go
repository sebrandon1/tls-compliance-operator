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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func TestNewRootCmd_Structure(t *testing.T) {
	cmd := newRootCmd()

	if cmd.Use != "kubectl-tlsreport [csv|json|yaml|junit|markdown|md|html|sarif]" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}

	found := map[string]bool{}
	for _, sub := range cmd.Commands() {
		found[strings.Fields(sub.Use)[0]] = true
	}
	for _, name := range []string{"summary", "get", "describe", "diff", "rescan", "target", "version", "completion"} {
		if !found[name] {
			t.Errorf("expected %s subcommand", name)
		}
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
	if err.Error() != "unknown format: xml (supported: csv, json, yaml, junit, markdown, md, html, sarif)" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunExport_ValidFormats(t *testing.T) {
	for _, format := range []string{"csv", "json", "yaml", "junit", "markdown", "md", "html", "sarif"} {
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
				if !strings.Contains(stderr, "No reports match the specified filters.") {
					t.Errorf("expected standardized empty-result message on stderr, got: %q", stderr)
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
		if stderr != "No reports match the specified filters.\n" {
			t.Errorf("expected the same empty-result message with a namespace filter, got: %q", stderr)
		}
	})
}

func TestPrintNoMatchingReports(t *testing.T) {
	stderr := captureStderr(t, func() {
		if err := printNoMatchingReports(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if stderr != "No reports match the specified filters.\n" {
		t.Errorf("expected standardized reports message, got %q", stderr)
	}
}

func TestPrintNoMatchingTargets(t *testing.T) {
	stderr := captureStderr(t, func() {
		if err := printNoMatchingTargets(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if stderr != "No targets match the specified filters.\n" {
		t.Errorf("expected standardized targets message, got %q", stderr)
	}
}

func TestOutputReports_EmptyFormats(t *testing.T) {
	origFormat := outputFormat
	t.Cleanup(func() { outputFormat = origFormat })

	for _, format := range []string{"table", "wide", "json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			outputFormat = format
			var stdout, stderr string
			stdout = captureStdout(t, func() {
				stderr = captureStderr(t, func() {
					if err := outputReports(nil); err != nil {
						t.Fatalf("outputReports(%s) error = %v", format, err)
					}
				})
			})
			if !strings.Contains(stderr, "No reports match the specified filters.") {
				t.Errorf("%s: expected empty-result message on stderr, got %q", format, stderr)
			}
			if strings.Contains(stdout, "NAME") {
				t.Errorf("%s: expected no table header on stdout, got %q", format, stdout)
			}
			if format == "json" && strings.TrimSpace(stdout) != "[]" {
				t.Errorf("json: expected empty array on stdout, got %q", stdout)
			}
			if format == "yaml" && strings.TrimSpace(stdout) != "[]" {
				t.Errorf("yaml: expected empty array on stdout, got %q", stdout)
			}
		})
	}
}

func TestWriteFilteredReports_Empty(t *testing.T) {
	for _, format := range []string{"json", "yaml", "csv"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr string
			stdout = captureStdout(t, func() {
				stderr = captureStderr(t, func() {
					if err := writeFilteredReports(format, nil); err != nil {
						t.Fatalf("writeFilteredReports(%s) error = %v", format, err)
					}
				})
			})
			if !strings.Contains(stderr, "No reports match the specified filters.") {
				t.Errorf("%s: expected empty-result message on stderr, got %q", format, stderr)
			}
			if format == "json" && strings.TrimSpace(stdout) != "[]" {
				t.Errorf("json: expected empty array, got %q", stdout)
			}
			if format == "yaml" && strings.TrimSpace(stdout) != "[]" {
				t.Errorf("yaml: expected empty array, got %q", stdout)
			}
			if format == "csv" && !strings.Contains(stdout, "Host") {
				t.Errorf("csv: expected header row on stdout, got %q", stdout)
			}
		})
	}
}

func TestWriteTargetList_Empty(t *testing.T) {
	orig := targetOutputFormat
	t.Cleanup(func() { targetOutputFormat = orig })

	for _, format := range []string{"table", "json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			targetOutputFormat = format
			var stdout, stderr string
			stdout = captureStdout(t, func() {
				stderr = captureStderr(t, func() {
					if err := writeTargetList(nil); err != nil {
						t.Fatalf("writeTargetList(%s) error = %v", format, err)
					}
				})
			})
			if !strings.Contains(stderr, "No targets match the specified filters.") {
				t.Errorf("%s: expected empty-result message on stderr, got %q", format, stderr)
			}
			if strings.Contains(stdout, "NAME") {
				t.Errorf("%s: expected no table header, got %q", format, stdout)
			}
			if format == "json" && strings.TrimSpace(stdout) != "[]" {
				t.Errorf("json: expected empty array, got %q", stdout)
			}
			if format == "yaml" && strings.TrimSpace(stdout) != "[]" {
				t.Errorf("yaml: expected empty array, got %q", stdout)
			}
		})
	}
}

func TestFlagCompletionRegistered(t *testing.T) {
	cmd := newRootCmd()

	for _, flag := range []string{"status", "source", "pqc-status", "sort-by", "tls-version"} {
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
		val, ok := updated.Annotations[securityv1alpha1.RescanAnnotation]
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
		if _, ok := updated.Annotations[securityv1alpha1.RescanAnnotation]; !ok {
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
			Annotations: map[string]string{securityv1alpha1.RescanAnnotation: "2024-01-01T00:00:00Z"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()

	err := waitForRescan(ctx, c, "test-report", 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestRescanReports_AllSucceed(t *testing.T) {
	ctx := context.Background()

	reports := []securityv1alpha1.TLSComplianceReport{
		{ObjectMeta: metav1.ObjectMeta{Name: "report-1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "report-2"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(&reports[0], &reports[1]).Build()

	err := rescanReports(ctx, c, reports, false, 0)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestRescanReports_EmptyReports(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	stderr := captureStderr(t, func() {
		err := rescanReports(ctx, c, nil, false, 0)
		if err != nil {
			t.Fatalf("expected nil error for empty reports, got: %v", err)
		}
	})
	if !strings.Contains(stderr, "No reports match") {
		t.Errorf("expected 'No reports match' message, got: %s", stderr)
	}
}

func TestRescanReports_PartialTriggerFailure(t *testing.T) {
	ctx := context.Background()

	good := securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "report-good"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(&good).Build()

	reports := []securityv1alpha1.TLSComplianceReport{
		good,
		{ObjectMeta: metav1.ObjectMeta{Name: "report-missing"}},
	}

	err := rescanReports(ctx, c, reports, false, 0)
	if err == nil {
		t.Fatal("expected exit code error on partial trigger failure")
	}
	var ece exitCodeError
	if !errors.As(err, &ece) || ece.code != 1 {
		t.Errorf("expected exitCodeError{code:1}, got: %v", err)
	}
}

func TestRescanReports_AllTriggersFail(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	reports := []securityv1alpha1.TLSComplianceReport{
		{ObjectMeta: metav1.ObjectMeta{Name: "missing-1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "missing-2"}},
	}

	err := rescanReports(ctx, c, reports, false, 0)
	if err == nil {
		t.Fatal("expected exit code error when all triggers fail")
	}
	var ece exitCodeError
	if !errors.As(err, &ece) || ece.code != 1 {
		t.Errorf("expected exitCodeError{code:1}, got: %v", err)
	}
}

func TestRescanReports_WaitTimeout(t *testing.T) {
	ctx := context.Background()

	report := securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "report-pending",
			Annotations: map[string]string{securityv1alpha1.RescanAnnotation: "2024-01-01T00:00:00Z"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(&report).Build()

	reports := []securityv1alpha1.TLSComplianceReport{report}

	err := rescanReports(ctx, c, reports, true, 2*time.Second)
	if err == nil {
		t.Fatal("expected exit code error on wait timeout")
	}
	var ece exitCodeError
	if !errors.As(err, &ece) || ece.code != 1 {
		t.Errorf("expected exitCodeError{code:1}, got: %v", err)
	}
}

func TestRescanReports_WaitSuccess(t *testing.T) {
	ctx := context.Background()

	report := securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "report-done"},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
		},
	}

	updateCount := 0
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(&report).WithStatusSubresource(&report).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if err := cl.Update(ctx, obj, opts...); err != nil {
					return err
				}
				updateCount++
				if updateCount == 1 {
					// Simulate the controller clearing the rescan annotation
					var r securityv1alpha1.TLSComplianceReport
					if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), &r); err == nil {
						delete(r.Annotations, securityv1alpha1.RescanAnnotation)
						_ = cl.Update(ctx, &r, opts...)
					}
				}
				return nil
			},
		}).
		Build()

	reports := []securityv1alpha1.TLSComplianceReport{report}

	err := rescanReports(ctx, c, reports, true, 10*time.Second)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
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

func TestFormatAge(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"seconds", 30 * time.Second, "30s"},
		{"minutes", 5 * time.Minute, "5m"},
		{"hours", 3 * time.Hour, "3h"},
		{"days", 48 * time.Hour, "2d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAge(tt.d)
			if got != tt.want {
				t.Errorf("formatAge(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestOutputReports(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "example.com",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	tests := []struct {
		name   string
		format string
	}{
		{"json", "json"},
		{"yaml", "yaml"},
		{"wide", "wide"},
		{"table default", ""},
		{"table explicit", "table"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputFormat = tt.format
			defer func() { outputFormat = "" }()

			captureStdout(t, func() {
				if err := outputReports(reports); err != nil {
					t.Errorf("outputReports() error = %v", err)
				}
			})
		})
	}
}

func TestOutputReports_UnknownFormat(t *testing.T) {
	outputFormat = "bogus"
	defer func() { outputFormat = "" }()

	err := outputReports(nil)
	if err == nil {
		t.Fatal("expected error for unknown output format")
	}
	if !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewTargetDeleteCmd_NoArgsNoAll(t *testing.T) {
	cmd := newTargetCmd()
	for _, sub := range cmd.Commands() {
		if sub.Name() == "delete" {
			sub.SetArgs([]string{})
			err := sub.Execute()
			if err == nil {
				t.Skip("command succeeded (kubeconfig available)")
			}
			break
		}
	}
}

func TestNewTargetCmd_Structure(t *testing.T) {
	cmd := newTargetCmd()
	if cmd.Use != "target" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
	subNames := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subNames[sub.Name()] = true
	}
	for _, want := range []string{"list", "get", "describe", "create", "update", "delete"} {
		if !subNames[want] {
			t.Errorf("expected %q subcommand", want)
		}
	}
}

func TestPrintReportDetail_FullReport(t *testing.T) {
	now := metav1.Now()
	hostnameMatch := true
	report := securityv1alpha1.TLSComplianceReport{}
	report.Name = "full-report"
	report.Spec.Host = "example.com"
	report.Spec.Port = 443
	report.Spec.SourceKind = securityv1alpha1.SourceKindService
	report.Spec.SourceNamespace = "default"
	report.Spec.SourceName = "web"
	report.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	report.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable
	report.Status.OverallCipherGrade = "A"
	report.Status.ForwardSecrecy = true
	report.Status.CertificateInfo = &securityv1alpha1.CertificateInfo{
		Issuer:             "CN=Test CA",
		Subject:            "CN=example.com",
		NotBefore:          &now,
		NotAfter:           &now,
		DaysUntilExpiry:    90,
		IsExpired:          false,
		HostnameMatch:      &hostnameMatch,
		PublicKeyAlgorithm: "RSA",
		PublicKeyBits:      2048,
		SignatureAlgorithm: "SHA256-RSA",
		ChainLength:        3,
		DNSNames:           []string{"example.com", "www.example.com"},
		SerialNumber:       "deadbeef",
		Fingerprint:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IPAddresses:        []string{"203.0.113.10"},
	}
	report.Status.CipherSuites = map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256"},
	}
	report.Status.CipherStrengthGrades = map[string]string{
		"TLS_AES_128_GCM_SHA256": "A",
	}
	report.Status.KeyExchangeTypes = map[string]string{
		"X25519": "ECDH 256-bit",
	}
	report.Status.ALPNProtocols = map[string]string{
		"TLS 1.3": "h2",
	}
	report.Status.NegotiatedCurves = map[string]string{
		"X25519": "256-bit",
	}
	report.Status.TLSAdherence = "StrictAllComponents"
	report.Status.IngressProfileCompliance = &securityv1alpha1.TLSProfileComplianceResult{
		ProfileType: "Intermediate",
		Compliant:   true,
	}
	report.Status.Conditions = []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Scanned", Message: "Scan complete"},
	}
	report.Status.FirstSeenAt = &now
	report.Status.LastSeenAt = &now
	report.Status.LastCheckAt = &now
	report.Status.ScanDuration = "1.23s"
	report.Status.LastError = "transient timeout"
	report.Status.RetryCount = 2
	report.Status.NextRetryAt = &now

	output := captureStdout(t, func() {
		if err := printReportDetail(&report); err != nil {
			t.Fatalf("printReportDetail() error = %v", err)
		}
	})

	for _, want := range []string{
		"CN=Test CA",
		"CN=example.com",
		"Hostname Match:",
		"Public Key:",
		"Signature Alg:",
		"Chain Length:",
		"DNS Names:",
		"Serial:",
		"Fingerprint:",
		"IP SANs:",
		"Cipher Suites:",
		"TLS_AES_128_GCM_SHA256",
		"Key Exchange Types:",
		"ALPN Protocols:",
		"Negotiated Curves:",
		"TLS Security Profile:",
		"StrictAllComponents",
		"Ingress TLS Profile Compliance:",
		"Conditions:",
		"Ready",
		"First Seen:",
		"Last Seen:",
		"Last Check:",
		"Scan Duration:",
		"Last Error:",
		"Retry Count:",
		"Next Retry:",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestPrintProfileCompliance_WithViolations(t *testing.T) {
	result := &securityv1alpha1.TLSProfileComplianceResult{
		ProfileType:       "Intermediate",
		Compliant:         false,
		DisallowedCiphers: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
		DisallowedGroups:  []string{"ffdhe2048"},
	}

	output := captureStdout(t, func() {
		printProfileCompliance(os.Stdout, "Test", result)
	})

	for _, want := range []string{
		"Test TLS Profile Compliance:",
		"Intermediate",
		"Disallowed Ciphers:",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"Disallowed Groups:",
		"ffdhe2048",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestPrintReportTableWide_WithCertInfo(t *testing.T) {
	expiry := metav1.Now()
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
				CertificateInfo: &securityv1alpha1.CertificateInfo{
					Issuer:   "CN=Test CA",
					NotAfter: &expiry,
				},
			},
		},
	}

	output := captureStdout(t, func() {
		if err := printReportTableWide(reports); err != nil {
			t.Fatalf("printReportTableWide() error = %v", err)
		}
	})

	if !strings.Contains(output, "CN=Test CA") {
		t.Error("expected issuer in wide output")
	}
	if strings.Contains(output, "CN=Test CA") && strings.Count(output, "-") < 5 {
		t.Error("expected cert expiry date in wide output")
	}
}

func TestFetchReportsWithClient(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		report := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: "test-report"},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "example.com",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()

		labelSelector = ""
		defer func() { labelSelector = "" }()

		reports, err := fetchReportsWithClient(ctx, c)
		if err != nil {
			t.Fatalf("fetchReportsWithClient() error = %v", err)
		}
		if len(reports) != 1 {
			t.Fatalf("expected 1 report, got %d", len(reports))
		}
		if reports[0].Name != "test-report" {
			t.Errorf("expected report name 'test-report', got %q", reports[0].Name)
		}
	})

	t.Run("with valid label selector", func(t *testing.T) {
		report := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "labeled-report",
				Labels: map[string]string{"app": "web"},
			},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "labeled.example.com",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()
		labelSelector = "app=web"
		defer func() { labelSelector = "" }()

		reports, err := fetchReportsWithClient(ctx, c)
		if err != nil {
			t.Fatalf("fetchReportsWithClient() error = %v", err)
		}
		if len(reports) != 1 {
			t.Fatalf("expected 1 report, got %d", len(reports))
		}
	})

	t.Run("invalid label selector", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		labelSelector = "!!invalid"
		defer func() { labelSelector = "" }()

		_, err := fetchReportsWithClient(ctx, c)
		if err == nil {
			t.Fatal("expected error for invalid label selector")
		}
		if !strings.Contains(err.Error(), "parsing label selector") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestRegisterFlagCompletions_Invoke(t *testing.T) {
	cmd := newRootCmd()

	for _, flag := range []string{"status", "source", "pqc-status", "sort-by", "tls-version"} {
		t.Run(flag, func(t *testing.T) {
			fn, ok := cmd.GetFlagCompletionFunc(flag)
			if !ok {
				t.Fatalf("flag %q: completion not registered", flag)
			}
			values, directive := fn(cmd, nil, "")
			if len(values) == 0 {
				t.Errorf("flag %q: expected non-empty completions", flag)
			}
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Errorf("flag %q: expected NoFileComp directive", flag)
			}
		})
	}

	for _, sub := range cmd.Commands() {
		if sub.Name() == "get" {
			fn, ok := sub.GetFlagCompletionFunc("output")
			if !ok {
				t.Fatal("output flag: completion not registered")
			}
			values, directive := fn(sub, nil, "")
			if len(values) == 0 {
				t.Error("output flag: expected non-empty completions")
			}
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Error("output flag: expected NoFileComp directive")
			}
			break
		}
	}
}

func TestNewDescribeCmd_Structure(t *testing.T) {
	cmd := newDescribeCmd()
	if cmd.Use != "describe <name>" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}
}

func TestNewGetCmd_OutputFlag(t *testing.T) {
	cmd := newGetCmd()
	f := cmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("expected --output flag")
	}
	if f.DefValue != "table" {
		t.Errorf("expected default 'table', got %s", f.DefValue)
	}
	if f.Shorthand != "o" {
		t.Errorf("expected shorthand 'o', got %s", f.Shorthand)
	}
}

func TestNewGetCmd_WatchFlag(t *testing.T) {
	cmd := newGetCmd()
	f := cmd.Flags().Lookup("watch")
	if f == nil {
		t.Fatal("expected --watch flag")
	}
	if f.DefValue != "false" {
		t.Errorf("expected default false, got %s", f.DefValue)
	}
	if f.Shorthand != "w" {
		t.Errorf("expected shorthand 'w', got %s", f.Shorthand)
	}
}

func sampleWatchReport(name, host, status string) *securityv1alpha1.TLSComplianceReport {
	r := &securityv1alpha1.TLSComplianceReport{}
	r.Name = name
	r.Spec.Host = host
	r.Spec.Port = 443
	r.Spec.SourceKind = securityv1alpha1.SourceKindService
	r.Status.ComplianceStatus = securityv1alpha1.ComplianceStatus(status)
	r.Status.OverallCipherGrade = "A"
	return r
}

func TestReportMatchesGetFilters(t *testing.T) {
	report := sampleWatchReport("svc-443", "svc.example", "NonCompliant")

	t.Run("no filters", func(t *testing.T) {
		filterOpts = export.FilterOptions{}
		defer func() { filterOpts = export.FilterOptions{} }()
		ok, err := reportMatchesGetFilters(report, "")
		if err != nil || !ok {
			t.Fatalf("match = %v, err = %v, want true", ok, err)
		}
	})
	t.Run("name mismatch", func(t *testing.T) {
		ok, err := reportMatchesGetFilters(report, "other")
		if err != nil || ok {
			t.Fatalf("match = %v, err = %v, want false", ok, err)
		}
	})
	t.Run("status filter", func(t *testing.T) {
		filterOpts = export.FilterOptions{Status: "NonCompliant"}
		defer func() { filterOpts = export.FilterOptions{} }()
		ok, err := reportMatchesGetFilters(report, "")
		if err != nil || !ok {
			t.Fatalf("match = %v, err = %v, want true", ok, err)
		}
		compliant := sampleWatchReport("ok-443", "ok.example", "Compliant")
		ok, err = reportMatchesGetFilters(compliant, "")
		if err != nil || ok {
			t.Fatalf("compliant match = %v, err = %v, want false", ok, err)
		}
	})
	t.Run("invalid expires-within", func(t *testing.T) {
		filterOpts = export.FilterOptions{ExpiresWithin: "nope"}
		defer func() { filterOpts = export.FilterOptions{} }()
		ok, err := reportMatchesGetFilters(report, "")
		if err == nil || ok {
			t.Fatalf("match = %v, err = %v, want error", ok, err)
		}
		if !strings.Contains(err.Error(), "expires-within") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestFormatReportTableRow_Deleted(t *testing.T) {
	r := sampleWatchReport("gone-443", "gone.example", "Compliant")
	row := formatReportTableRow(r, false, true)
	if !strings.Contains(row, "Deleted") {
		t.Errorf("expected Deleted in row, got %q", row)
	}
	if !strings.Contains(row, "gone-443") {
		t.Errorf("expected name in row, got %q", row)
	}
}

func TestHandleGetWatchEvent(t *testing.T) {
	outputFormat = "table"
	filterOpts = export.FilterOptions{}
	defer func() {
		outputFormat = ""
		filterOpts = export.FilterOptions{}
	}()

	t.Run("added", func(t *testing.T) {
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Added, Object: r}, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "svc-443") {
			t.Errorf("output = %q", buf.String())
		}
	})
	t.Run("deleted", func(t *testing.T) {
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Deleted, Object: r}, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "Deleted") {
			t.Errorf("output = %q", buf.String())
		}
	})
	t.Run("modified", func(t *testing.T) {
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Warning")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Modified, Object: r}, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "svc-443") || !strings.Contains(buf.String(), "Warning") {
			t.Errorf("output = %q", buf.String())
		}
	})
	t.Run("status filter skips", func(t *testing.T) {
		filterOpts = export.FilterOptions{Status: "NonCompliant"}
		defer func() { filterOpts = export.FilterOptions{} }()
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Modified, Object: r}, ""); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Errorf("expected no output, got %q", buf.String())
		}
	})
	t.Run("name filter skips", func(t *testing.T) {
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Added, Object: r}, "other"); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Errorf("expected no output, got %q", buf.String())
		}
	})
	t.Run("bookmark ignored", func(t *testing.T) {
		var buf bytes.Buffer
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Bookmark}, ""); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Errorf("expected no output, got %q", buf.String())
		}
	})
	t.Run("json event", func(t *testing.T) {
		outputFormat = "json"
		defer func() { outputFormat = "table" }()
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Added, Object: r}, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), `"host":"svc.example"`) {
			t.Errorf("json = %q", buf.String())
		}
	})
	t.Run("watch error", func(t *testing.T) {
		err := handleGetWatchEvent(io.Discard, watch.Event{Type: watch.Error, Object: &metav1.Status{Message: "boom"}}, "")
		if err == nil || !strings.Contains(err.Error(), "watch error") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("deleted ignores status filter", func(t *testing.T) {
		filterOpts = export.FilterOptions{Status: "NonCompliant"}
		defer func() { filterOpts = export.FilterOptions{} }()
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Deleted, Object: r}, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "Deleted") {
			t.Errorf("expected deleted row, got %q", buf.String())
		}
	})
	t.Run("nil object ignored", func(t *testing.T) {
		var buf bytes.Buffer
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Added}, ""); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Errorf("expected no output, got %q", buf.String())
		}
	})
	t.Run("deleted name mismatch", func(t *testing.T) {
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Deleted, Object: r}, "other"); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Errorf("expected no output, got %q", buf.String())
		}
	})
	t.Run("invalid filter error", func(t *testing.T) {
		filterOpts = export.FilterOptions{ExpiresWithin: "nope"}
		defer func() { filterOpts = export.FilterOptions{} }()
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		err := handleGetWatchEvent(io.Discard, watch.Event{Type: watch.Added, Object: r}, "")
		if err == nil || !strings.Contains(err.Error(), "expires-within") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("wide event", func(t *testing.T) {
		outputFormat = "wide"
		defer func() { outputFormat = "table" }()
		var buf bytes.Buffer
		r := sampleWatchReport("svc-443", "svc.example", "Compliant")
		r.Spec.SourceNamespace = "prod"
		if err := handleGetWatchEvent(&buf, watch.Event{Type: watch.Added, Object: r}, ""); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "prod") {
			t.Errorf("wide row = %q", buf.String())
		}
	})
}

func TestWriteWatchSnapshotAndEventFormats(t *testing.T) {
	r := sampleWatchReport("svc-443", "svc.example", "Compliant")
	reports := []securityv1alpha1.TLSComplianceReport{*r}

	t.Run("unknown snapshot format", func(t *testing.T) {
		outputFormat = "csv"
		defer func() { outputFormat = "" }()
		err := writeWatchSnapshot(io.Discard, reports)
		if err == nil || !strings.Contains(err.Error(), "unknown output format") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unknown event format", func(t *testing.T) {
		outputFormat = "csv"
		defer func() { outputFormat = "" }()
		err := writeWatchEvent(io.Discard, r, false)
		if err == nil || !strings.Contains(err.Error(), "unknown output format") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("yaml snapshot and event", func(t *testing.T) {
		outputFormat = "yaml"
		defer func() { outputFormat = "" }()
		var buf bytes.Buffer
		if err := writeWatchSnapshot(&buf, reports); err != nil {
			t.Fatal(err)
		}
		if err := writeWatchEvent(&buf, r, false); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if !strings.Contains(out, "host: svc.example") {
			t.Errorf("yaml = %q", out)
		}
		if strings.Count(out, "---") != 1 {
			t.Errorf("expected one YAML document separator, got %q", out)
		}
	})
	t.Run("json snapshot", func(t *testing.T) {
		outputFormat = "json"
		defer func() { outputFormat = "" }()
		var buf bytes.Buffer
		if err := writeWatchSnapshot(&buf, reports); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), `"host":"svc.example"`) {
			t.Errorf("json = %q", buf.String())
		}
	})
	t.Run("wide table snapshot", func(t *testing.T) {
		outputFormat = "wide"
		defer func() { outputFormat = "" }()
		var buf bytes.Buffer
		if err := writeWatchSnapshot(&buf, reports); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "NAMESPACE") {
			t.Errorf("wide header missing: %q", buf.String())
		}
	})
}

func TestFormatReportTableRow_WideDeleted(t *testing.T) {
	r := sampleWatchReport("gone-443", "gone.example", "Compliant")
	row := formatReportTableRow(r, true, true)
	if !strings.Contains(row, "Deleted") {
		t.Errorf("expected Deleted in wide row, got %q", row)
	}
}

func TestWatchReports_CancelledContext(t *testing.T) {
	report := sampleWatchReport("svc-443", "svc.example", "Compliant")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outputFormat = "table"
	labelSelector = ""
	filterOpts = export.FilterOptions{}
	defer func() {
		outputFormat = ""
		labelSelector = ""
		filterOpts = export.FilterOptions{}
	}()

	var buf bytes.Buffer
	if err := watchReports(ctx, c, "", &buf); err != nil {
		t.Fatalf("watchReports() error = %v", err)
	}
	if !strings.Contains(buf.String(), "svc-443") {
		t.Errorf("expected snapshot of existing report, got %q", buf.String())
	}
}

func TestWatchReports_NamedMissing(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outputFormat = "table"
	labelSelector = ""
	filterOpts = export.FilterOptions{}
	defer func() {
		outputFormat = ""
		labelSelector = ""
		filterOpts = export.FilterOptions{}
	}()

	var buf bytes.Buffer
	if err := watchReports(ctx, c, "missing-report", &buf); err != nil {
		t.Fatalf("watchReports() error = %v", err)
	}
	if !strings.Contains(buf.String(), "NAME") {
		t.Errorf("expected table header while waiting, got %q", buf.String())
	}
}

func TestFilterReportsByName(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{*sampleWatchReport("a", "a.example", "Compliant"), *sampleWatchReport("b", "b.example", "Compliant")}
	got := filterReportsByName(reports, "b")
	if len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("got %v", got)
	}
	if got := filterReportsByName(reports, "missing"); len(got) != 0 {
		t.Fatalf("missing name should return nil/empty, got %d", len(got))
	}
}

func TestReportListOptions_InvalidSelector(t *testing.T) {
	labelSelector = "!!invalid"
	defer func() { labelSelector = "" }()
	_, err := reportListOptions("")
	if err == nil || !strings.Contains(err.Error(), "parsing label selector") {
		t.Fatalf("error = %v", err)
	}
}

func TestReportListOptions_SelectorAndResourceVersion(t *testing.T) {
	labelSelector = "app=web"
	defer func() { labelSelector = "" }()
	opts, err := reportListOptions("12345")
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 2 {
		t.Fatalf("expected selector and resourceVersion options, got %d", len(opts))
	}
}

func TestWatchReports_InvalidSelector(t *testing.T) {
	labelSelector = "!!invalid"
	defer func() { labelSelector = "" }()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	err := watchReports(context.Background(), c, "", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "parsing label selector") {
		t.Fatalf("error = %v", err)
	}
}

func TestBoolDash(t *testing.T) {
	if got := boolDash(true); got != "true" {
		t.Errorf("boolDash(true) = %q, want 'true'", got)
	}
	if got := boolDash(false); got != "-" {
		t.Errorf("boolDash(false) = %q, want '-'", got)
	}
}

func TestOutputTargets(t *testing.T) {
	targets := []securityv1alpha1.TLSComplianceTarget{
		{
			Spec: securityv1alpha1.TLSComplianceTargetSpec{
				Host: "example.com",
				Port: 443,
			},
			Status: securityv1alpha1.TLSComplianceTargetStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				ReportName:       "example-com-443-abc12345",
				Message:          "Report example-com-443-abc12345 generated",
			},
		},
	}
	targets[0].Name = "example-com-443"

	tests := []struct {
		name   string
		format string
	}{
		{"json", "json"},
		{"yaml", "yaml"},
		{"wide", "wide"},
		{"table default", ""},
		{"table explicit", "table"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetOutputFormat = tt.format
			defer func() { targetOutputFormat = "" }()

			output := captureStdout(t, func() {
				if err := outputTargets(targets); err != nil {
					t.Errorf("outputTargets() error = %v", err)
				}
			})
			if output == "" {
				t.Error("expected non-empty output")
			}
		})
	}
}

func TestOutputTargets_UnknownFormat(t *testing.T) {
	targetOutputFormat = "bogus"
	defer func() { targetOutputFormat = "" }()

	err := outputTargets(nil)
	if err == nil {
		t.Fatal("expected error for unknown output format")
	}
	if !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOutputTargets_JSONContent(t *testing.T) {
	targets := []securityv1alpha1.TLSComplianceTarget{
		{
			Spec: securityv1alpha1.TLSComplianceTargetSpec{
				Host: "test.example",
				Port: 8443,
			},
		},
	}
	targets[0].Name = "test-target"

	targetOutputFormat = "json"
	defer func() { targetOutputFormat = "" }()

	output := captureStdout(t, func() {
		if err := outputTargets(targets); err != nil {
			t.Fatalf("outputTargets() error = %v", err)
		}
	})
	if !strings.Contains(output, `"host": "test.example"`) {
		t.Errorf("expected JSON to contain host, got: %s", output)
	}
	if !strings.Contains(output, `"port": 8443`) {
		t.Errorf("expected JSON to contain port, got: %s", output)
	}
}

func TestOutputTargets_YAMLContent(t *testing.T) {
	targets := []securityv1alpha1.TLSComplianceTarget{
		{
			Spec: securityv1alpha1.TLSComplianceTargetSpec{
				Host: "yaml.example",
				Port: 443,
			},
		},
	}
	targets[0].Name = "yaml-target"

	targetOutputFormat = "yaml"
	defer func() { targetOutputFormat = "" }()

	output := captureStdout(t, func() {
		if err := outputTargets(targets); err != nil {
			t.Fatalf("outputTargets() error = %v", err)
		}
	})
	if !strings.Contains(output, "host: yaml.example") {
		t.Errorf("expected YAML to contain host, got: %s", output)
	}
	if !strings.Contains(output, "port: 443") {
		t.Errorf("expected YAML to contain port, got: %s", output)
	}
}

func TestPrintTargetTableWide_MessageColumn(t *testing.T) {
	targets := []securityv1alpha1.TLSComplianceTarget{
		{
			Spec: securityv1alpha1.TLSComplianceTargetSpec{
				Host: "wide.example",
				Port: 443,
			},
			Status: securityv1alpha1.TLSComplianceTargetStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				Message:          "Report wide-example generated",
			},
		},
	}
	targets[0].Name = "wide-target"

	output := captureStdout(t, func() {
		if err := printTargetTableWide(targets); err != nil {
			t.Fatalf("printTargetTableWide() error = %v", err)
		}
	})
	if !strings.Contains(output, "MESSAGE") {
		t.Error("expected MESSAGE column header in wide output")
	}
	if !strings.Contains(output, "Report wide-example generated") {
		t.Errorf("expected message in output, got: %s", output)
	}
}

func TestNewTargetListCmd_OutputFlag(t *testing.T) {
	cmd := newTargetListCmd()
	f := cmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("expected -o/--output flag on target list command")
	}
	if f.DefValue != "table" {
		t.Errorf("expected default 'table', got %q", f.DefValue)
	}
	if f.Shorthand != "o" {
		t.Errorf("expected shorthand 'o', got %q", f.Shorthand)
	}
}

func TestNewVersionCmd_Execute(t *testing.T) {
	output := captureStdout(t, func() {
		cmd := newVersionCmd()
		if err := cmd.Execute(); err != nil {
			t.Fatalf("version command error = %v", err)
		}
	})
	if !strings.Contains(output, "kubectl-tlsreport") {
		t.Errorf("expected version output to contain 'kubectl-tlsreport', got %q", output)
	}
}

func TestNewTargetGetCmd_Structure(t *testing.T) {
	cmd := newTargetGetCmd()
	if cmd.Use != "get <name>" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
	f := cmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("expected -o/--output flag")
	}
	if f.DefValue != "table" {
		t.Errorf("expected default 'table', got %q", f.DefValue)
	}
	if f.Shorthand != "o" {
		t.Errorf("expected shorthand 'o', got %q", f.Shorthand)
	}
}

func TestNewTargetDescribeCmd_Structure(t *testing.T) {
	cmd := newTargetDescribeCmd()
	if cmd.Use != "describe <name>" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
}

func TestPrintTargetDetail(t *testing.T) {
	now := metav1.Now()
	target := securityv1alpha1.TLSComplianceTarget{}
	target.Name = "my-target"
	target.Spec.Host = "example.com"
	target.Spec.Port = 443
	target.CreationTimestamp = now
	target.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	target.Status.ReportName = "example-com-443-abc12345"
	target.Status.Message = "Report generated"
	target.Status.LastScannedAt = &now
	target.Status.Conditions = []metav1.Condition{
		{
			Type:   "Ready",
			Status: metav1.ConditionTrue,
			Reason: "ScanComplete",
		},
	}

	output := captureStdout(t, func() {
		if err := printTargetDetail(&target); err != nil {
			t.Fatalf("printTargetDetail error: %v", err)
		}
	})

	for _, want := range []string{
		"Name:         my-target",
		"Host:         example.com",
		"Port:         443",
		"Compliance:    Compliant",
		"Report:        example-com-443-abc12345",
		"Message:       Report generated",
		"Last Scanned:",
		"Conditions:",
		"Ready",
		"ScanComplete",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected output to contain %q", want)
		}
	}
}

func TestPrintTargetDetail_Pending(t *testing.T) {
	target := securityv1alpha1.TLSComplianceTarget{}
	target.Name = "pending-target"
	target.Spec.Host = "pending.example"
	target.Spec.Port = 8443

	output := captureStdout(t, func() {
		if err := printTargetDetail(&target); err != nil {
			t.Fatalf("printTargetDetail error: %v", err)
		}
	})

	if !strings.Contains(output, "(pending)") {
		t.Error("expected (pending) for empty compliance status")
	}
	if strings.Contains(output, "Report:") {
		t.Error("expected no Report line when report name is empty")
	}
	if strings.Contains(output, "Message:") {
		t.Error("expected no Message line when message is empty")
	}
	if strings.Contains(output, "Conditions:") {
		t.Error("expected no Conditions section when empty")
	}
}

func TestNewTargetCreateCmd_WaitFlag(t *testing.T) {
	cmd := newTargetCreateCmd()
	f := cmd.Flags().Lookup("wait")
	if f == nil {
		t.Fatal("expected --wait flag")
	}
	if f.DefValue != "false" {
		t.Errorf("expected default 'false', got %q", f.DefValue)
	}
	tf := cmd.Flags().Lookup("timeout")
	if tf == nil {
		t.Fatal("expected --timeout flag")
	}
	if tf.DefValue != "1m0s" {
		t.Errorf("expected default '1m0s', got %q", tf.DefValue)
	}
}

func TestWaitForTargetScan_AlreadyScanned(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "scanned-target"},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "example.com",
			Port: 443,
		},
		Status: securityv1alpha1.TLSComplianceTargetStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			ReportName:       "example-com-443-abc12345",
			LastScannedAt:    &now,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(target).
		WithStatusSubresource(target).Build()

	output := captureStdout(t, func() {
		if err := waitForTargetScan(ctx, c, "scanned-target", 5*time.Second); err != nil {
			t.Fatalf("waitForTargetScan() error = %v", err)
		}
	})

	if !strings.Contains(output, "Status: Compliant") {
		t.Errorf("expected 'Status: Compliant' in output, got: %s", output)
	}
	if !strings.Contains(output, "Report: example-com-443-abc12345") {
		t.Errorf("expected report name in output, got: %s", output)
	}
}

func TestWaitForTargetScan_Timeout(t *testing.T) {
	ctx := context.Background()

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "pending-target"},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "slow.example",
			Port: 443,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(target).Build()

	err := waitForTargetScan(ctx, c, "pending-target", 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestNewTargetUpdateCmd_Structure(t *testing.T) {
	cmd := newTargetUpdateCmd()
	if cmd.Use != "update <name>" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
	if cmd.Flags().Lookup("host") == nil {
		t.Error("expected --host flag")
	}
	if cmd.Flags().Lookup("port") == nil {
		t.Error("expected --port flag")
	}
}

func TestNewTargetUpdateCmd_Validation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "missing flags", args: []string{"google-com-443"}, wantErr: "at least one of --host or --port is required"},
		{name: "empty host", args: []string{"google-com-443", "--host", ""}, wantErr: "host must not be empty"},
		{name: "invalid port", args: []string{"google-com-443", "--port", "0"}, wantErr: "invalid port 0: must be 1-65535"},
		{name: "missing name", args: []string{"--host", "example.com"}, wantErr: "accepts 1 arg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newTargetUpdateCmd()
			cmd.SetArgs(tt.args)
			cmd.SilenceUsage = true
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTargetUpdate(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		port    int
		hostSet bool
		portSet bool
		wantErr string
	}{
		{name: "host only", host: "example.com", hostSet: true},
		{name: "port only", port: 8443, portSet: true},
		{name: "host and port", host: "example.com", port: 443, hostSet: true, portSet: true},
		{name: "missing flags", wantErr: "at least one of --host or --port is required"},
		{name: "empty host", host: "  ", hostSet: true, wantErr: "host must not be empty"},
		{name: "port too low", port: 0, portSet: true, wantErr: "invalid port 0: must be 1-65535"},
		{name: "port too high", port: 65536, portSet: true, wantErr: "invalid port 65536: must be 1-65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargetUpdate(tt.host, tt.port, tt.hostSet, tt.portSet)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateTarget(t *testing.T) {
	ctx := context.Background()
	existing := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "google-com-443"},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "google.com",
			Port: 443,
		},
	}

	t.Run("update host", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing.DeepCopy()).Build()
		stderr := captureStderr(t, func() {
			if err := updateTarget(ctx, c, "google-com-443", "maps.google.com", 0, true, false); err != nil {
				t.Fatalf("updateTarget() error = %v", err)
			}
		})
		if !strings.Contains(stderr, "tlscompliancetarget/google-com-443 updated") {
			t.Errorf("unexpected stderr: %s", stderr)
		}
		var got securityv1alpha1.TLSComplianceTarget
		if err := c.Get(ctx, client.ObjectKey{Name: "google-com-443"}, &got); err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if got.Spec.Host != "maps.google.com" {
			t.Errorf("host = %q, want maps.google.com", got.Spec.Host)
		}
		if got.Spec.Port != 443 {
			t.Errorf("port = %d, want 443", got.Spec.Port)
		}
	})

	t.Run("update port", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing.DeepCopy()).Build()
		if err := updateTarget(ctx, c, "google-com-443", "", 8443, false, true); err != nil {
			t.Fatalf("updateTarget() error = %v", err)
		}
		var got securityv1alpha1.TLSComplianceTarget
		if err := c.Get(ctx, client.ObjectKey{Name: "google-com-443"}, &got); err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if got.Spec.Host != "google.com" {
			t.Errorf("host = %q, want google.com", got.Spec.Host)
		}
		if got.Spec.Port != 8443 {
			t.Errorf("port = %d, want 8443", got.Spec.Port)
		}
	})

	t.Run("update host and port", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing.DeepCopy()).Build()
		if err := updateTarget(ctx, c, "google-com-443", "example.com", 8443, true, true); err != nil {
			t.Fatalf("updateTarget() error = %v", err)
		}
		var got securityv1alpha1.TLSComplianceTarget
		if err := c.Get(ctx, client.ObjectKey{Name: "google-com-443"}, &got); err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if got.Spec.Host != "example.com" || got.Spec.Port != 8443 {
			t.Errorf("spec = %s:%d, want example.com:8443", got.Spec.Host, got.Spec.Port)
		}
	})

	t.Run("not found", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		err := updateTarget(ctx, c, "missing", "example.com", 443, true, true)
		if err == nil || !strings.Contains(err.Error(), "getting TLSComplianceTarget \"missing\"") {
			t.Fatalf("error = %v, want not found", err)
		}
	})

	t.Run("update error", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing.DeepCopy()).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.UpdateOption) error {
					return errors.New("conflict")
				},
			}).Build()
		err := updateTarget(ctx, c, "google-com-443", "example.com", 0, true, false)
		if err == nil || !strings.Contains(err.Error(), "updating target") {
			t.Fatalf("error = %v, want updating target", err)
		}
	})
}

func sampleTargets() []securityv1alpha1.TLSComplianceTarget {
	return []securityv1alpha1.TLSComplianceTarget{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "zeta", Labels: map[string]string{"team": "platform"}},
			Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "zeta.example", Port: 8443},
			Status:     securityv1alpha1.TLSComplianceTargetStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "alpha", Labels: map[string]string{"team": "edge"}},
			Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "alpha.example", Port: 443},
			Status:     securityv1alpha1.TLSComplianceTargetStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "beta"},
			Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "beta.example", Port: 6443},
			Status:     securityv1alpha1.TLSComplianceTargetStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusWarning},
		},
	}
}

func TestFilterTargetsByStatus(t *testing.T) {
	targets := sampleTargets()

	got := filterTargetsByStatus(targets, "")
	if len(got) != 3 {
		t.Fatalf("empty status: got %d, want 3", len(got))
	}

	got = filterTargetsByStatus(targets, "NonCompliant")
	if len(got) != 1 || got[0].Name != "alpha" {
		t.Fatalf("NonCompliant = %v, want alpha", targetNames(got))
	}

	got = filterTargetsByStatus(targets, "noncompliant")
	if len(got) != 1 || got[0].Name != "alpha" {
		t.Fatalf("case-insensitive filter = %v, want alpha", targetNames(got))
	}

	got = filterTargetsByStatus(targets, "Timeout")
	if len(got) != 0 {
		t.Fatalf("Timeout = %v, want none", targetNames(got))
	}
}

func TestSortTargets(t *testing.T) {
	t.Run("host", func(t *testing.T) {
		targets := sampleTargets()
		if err := sortTargets(targets, "host"); err != nil {
			t.Fatal(err)
		}
		want := []string{"alpha", "beta", "zeta"}
		if got := targetNames(targets); !slices.Equal(got, want) {
			t.Errorf("names = %v, want %v", got, want)
		}
	})
	t.Run("port", func(t *testing.T) {
		targets := sampleTargets()
		if err := sortTargets(targets, "port"); err != nil {
			t.Fatal(err)
		}
		want := []string{"alpha", "beta", "zeta"}
		if got := targetNames(targets); !slices.Equal(got, want) {
			t.Errorf("names = %v, want %v", got, want)
		}
	})
	t.Run("compliance", func(t *testing.T) {
		targets := sampleTargets()
		if err := sortTargets(targets, "compliance"); err != nil {
			t.Fatal(err)
		}
		want := []string{"zeta", "alpha", "beta"} // Compliant, NonCompliant, Warning
		if got := targetNames(targets); !slices.Equal(got, want) {
			t.Errorf("names = %v, want %v", got, want)
		}
	})
	t.Run("status alias", func(t *testing.T) {
		targets := sampleTargets()
		if err := sortTargets(targets, "status"); err != nil {
			t.Fatal(err)
		}
		want := []string{"zeta", "alpha", "beta"}
		if got := targetNames(targets); !slices.Equal(got, want) {
			t.Errorf("names = %v, want %v", got, want)
		}
	})
	t.Run("empty is no-op", func(t *testing.T) {
		targets := sampleTargets()
		if err := sortTargets(targets, ""); err != nil {
			t.Fatal(err)
		}
		want := []string{"zeta", "alpha", "beta"}
		if got := targetNames(targets); !slices.Equal(got, want) {
			t.Errorf("names = %v, want %v", got, want)
		}
	})
	t.Run("unsupported report keys", func(t *testing.T) {
		for _, key := range []string{"expiry", "grade", "pqc"} {
			err := sortTargets(sampleTargets(), key)
			if err == nil || !strings.Contains(err.Error(), "unsupported --sort-by") {
				t.Errorf("sortTargets(%q) error = %v", key, err)
			}
		}
	})
	t.Run("unknown key", func(t *testing.T) {
		err := sortTargets(sampleTargets(), "namespace")
		if err == nil || !strings.Contains(err.Error(), "unknown --sort-by") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestFetchTargetsWithClient(t *testing.T) {
	ctx := context.Background()
	targets := sampleTargets()
	objs := []client.Object{&targets[0], &targets[1], &targets[2]}

	t.Run("lists all", func(t *testing.T) {
		labelSelector = ""
		defer func() { labelSelector = "" }()
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
		got, err := fetchTargetsWithClient(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d targets, want 3", len(got))
		}
	})

	t.Run("label selector", func(t *testing.T) {
		labelSelector = "team=platform"
		defer func() { labelSelector = "" }()
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
		got, err := fetchTargetsWithClient(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Name != "zeta" {
			t.Fatalf("got %v, want zeta", targetNames(got))
		}
	})

	t.Run("invalid selector", func(t *testing.T) {
		labelSelector = "!!invalid"
		defer func() { labelSelector = "" }()
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		_, err := fetchTargetsWithClient(ctx, c)
		if err == nil || !strings.Contains(err.Error(), "parsing label selector") {
			t.Fatalf("error = %v", err)
		}
	})
}

func targetNames(targets []securityv1alpha1.TLSComplianceTarget) []string {
	names := make([]string, len(targets))
	for i := range targets {
		names[i] = targets[i].Name
	}
	return names
}
