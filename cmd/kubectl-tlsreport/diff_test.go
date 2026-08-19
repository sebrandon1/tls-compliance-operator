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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func TestNewDiffCmd(t *testing.T) {
	cmd := newDiffCmd()
	if cmd.Use != "diff <before-file> [after-file]" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}
	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}
	if cmd.Flags().Lookup("fail-on-regression") == nil {
		t.Error("expected --fail-on-regression flag")
	}
	if cmd.Flags().Lookup("output") == nil {
		t.Error("expected --output flag")
	}
}

func TestRunDiff_IdenticalSnapshots(t *testing.T) {
	dir := t.TempDir()
	snap := `[{"host":"app.example.com","port":"443","compliance":"Compliant","grade":"A","tls13":true,"tls12":true}]`
	before := writeSnapshot(t, dir, "before.json", snap)
	after := writeSnapshot(t, dir, "after.json", snap)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", before, after})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "No differences.") {
		t.Errorf("output = %q", out)
	}
}

func TestRunDiff_StatusChangeAndFailOnRegression(t *testing.T) {
	dir := t.TempDir()
	before := writeSnapshot(t, dir, "before.json",
		`[{"host":"app.example.com","port":"443","compliance":"Compliant","grade":"A"}]`)
	after := writeSnapshot(t, dir, "after.json",
		`[{"host":"app.example.com","port":"443","compliance":"NonCompliant","grade":"A"}]`)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", before, after, "--fail-on-regression"})
	var runErr error
	out := captureStdout(t, func() {
		runErr = cmd.Execute()
	})
	if !strings.Contains(out, "compliance: Compliant → NonCompliant") {
		t.Errorf("output = %q", out)
	}
	var ece exitCodeError
	if !errors.As(runErr, &ece) || ece.code != 1 {
		t.Fatalf("expected exit code 1, got %v", runErr)
	}
}

func TestRunDiff_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	before := writeSnapshot(t, dir, "before.json",
		`[{"host":"app.example.com","port":"443","compliance":"Compliant"}]`)
	after := writeSnapshot(t, dir, "after.json",
		`[{"host":"app.example.com","port":"443","compliance":"Compliant"},{"host":"new.example.com","port":"443","compliance":"Compliant"}]`)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", before, after, "-o", "json"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	var parsed export.SnapshotDiff
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if parsed.AfterCount != 2 || len(parsed.Added) != 1 {
		t.Fatalf("diff = %+v", parsed)
	}
	if parsed.Added[0].Host != "new.example.com" {
		t.Errorf("added host = %q", parsed.Added[0].Host)
	}
}

func TestRunDiff_MissingFile(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", filepath.Join(t.TempDir(), "missing.json")})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading snapshot") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunDiff_InvalidSnapshot(t *testing.T) {
	path := writeSnapshot(t, t.TempDir(), "bad.json", `{not-json`)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", path, path})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "parsing snapshot") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunDiff_UnknownOutput(t *testing.T) {
	dir := t.TempDir()
	snap := writeSnapshot(t, dir, "snap.json", `[]`)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", snap, snap, "-o", "xml"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected unknown format error")
	}
	if !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunDiff_FailOnRegressionIdenticalIsZero(t *testing.T) {
	dir := t.TempDir()
	snap := writeSnapshot(t, dir, "snap.json",
		`[{"host":"app.example.com","port":"443","compliance":"Compliant"}]`)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", snap, snap, "--fail-on-regression"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("identical snapshots should not fail: %v", err)
	}
}

func TestRunDiff_YAMLSnapshots(t *testing.T) {
	dir := t.TempDir()
	reports := []securityv1alpha1.TLSComplianceReport{{
		Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "app.example.com", Port: 443},
		Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant},
	}}
	var buf bytes.Buffer
	if err := export.WriteYAML(&buf, reports); err != nil {
		t.Fatal(err)
	}
	path := writeSnapshot(t, dir, "snap.yaml", buf.String())
	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", path, path})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "No differences.") {
		t.Errorf("output = %q", out)
	}
}

func TestRunDiff_LiveFetchMissingKubeconfig(t *testing.T) {
	path := writeSnapshot(t, t.TempDir(), "before.json", `[]`)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", path, "--kubeconfig", "/nonexistent/kubeconfig"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected kubeconfig error")
	}
}

func TestRunDiff_FiltersRejectedWithTwoFiles(t *testing.T) {
	dir := t.TempDir()
	snap := writeSnapshot(t, dir, "snap.json", `[]`)
	defer func() { filterOpts = export.FilterOptions{} }()
	cmd := newRootCmd()
	cmd.SetArgs([]string{"diff", snap, snap, "-n", "prod"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "filter flags apply only") {
		t.Fatalf("got %v", err)
	}
}

func writeSnapshot(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
