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
	"errors"
	"strings"
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestExpectedGroupsFlagsRegistered(t *testing.T) {
	cmd := newRootCmd()

	for _, flag := range []string{"expected-groups", "expected-groups-mode", "fail-on-group-mismatch"} {
		if f := cmd.PersistentFlags().Lookup(flag); f == nil {
			t.Errorf("expected persistent flag %q", flag)
		}
	}
	if f := cmd.PersistentFlags().Lookup("expected-groups-mode"); f != nil && f.DefValue != "contains" {
		t.Errorf("expected-groups-mode default = %q, want contains", f.DefValue)
	}
}

func TestCheckExitCode_ExpectedGroups(t *testing.T) {
	report := securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "example.com", Port: 443},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			NegotiatedCurves: map[string]string{"TLS 1.3": "X25519"},
		},
	}

	tests := []struct {
		name      string
		groups    string
		mode      string
		wantExit  bool
		wantError bool
	}{
		{name: "matching groups pass", groups: "X25519", mode: "contains"},
		{name: "missing group fails", groups: "X25519MLKEM768", mode: "contains", wantExit: true},
		{name: "exact match passes", groups: "X25519", mode: "exact"},
		{name: "exact mismatch fails", groups: "X25519MLKEM768", mode: "exact", wantExit: true},
		{name: "mismatch without fail flag is not enforced", groups: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectedGroups = tc.groups
			groupsMode = tc.mode
			failOnGroupMismatch = tc.groups != ""

			err := checkExitCode([]securityv1alpha1.TLSComplianceReport{report})
			t.Cleanup(func() {
				expectedGroups, groupsMode, failOnGroupMismatch = "", "contains", false
			})

			var ece exitCodeError
			if got := errors.As(err, &ece); got != tc.wantExit {
				t.Fatalf("checkExitCode() error = %v, wantExit %v", err, tc.wantExit)
			}
		})
	}
}

func TestWriteGroupsGate(t *testing.T) {
	report := securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "example.com", Port: 443},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			NegotiatedCurves: map[string]string{"TLS 1.3": "X25519"},
		},
	}

	expectedGroups = "X25519MLKEM768"
	groupsMode = "contains"
	t.Cleanup(func() { expectedGroups, groupsMode = "", "contains" })

	var sb strings.Builder
	if err := writeGroupsGate(&sb, []securityv1alpha1.TLSComplianceReport{report}); err != nil {
		t.Fatalf("writeGroupsGate() error = %v", err)
	}

	out := sb.String()
	for _, want := range []string{"Expected Groups (contains)", "missing:\tX25519MLKEM768"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteGroupsGate_NoExpectationIsSilent(t *testing.T) {
	expectedGroups = ""
	t.Cleanup(func() { expectedGroups = "" })

	var sb strings.Builder
	if err := writeGroupsGate(&sb, nil); err != nil {
		t.Fatalf("writeGroupsGate() error = %v", err)
	}
	if sb.Len() != 0 {
		t.Errorf("expected no output without --expected-groups, got:\n%s", sb.String())
	}
}

func TestWriteGroupsGate_InvalidMode(t *testing.T) {
	expectedGroups = "X25519"
	groupsMode = "subset"
	t.Cleanup(func() { expectedGroups, groupsMode = "", "contains" })

	var sb strings.Builder
	if err := writeGroupsGate(&sb, nil); err == nil {
		t.Fatal("expected an error for an invalid --expected-groups-mode")
	}
}

func TestCheckExitCode_FailOnGroupMismatchRequiresGroups(t *testing.T) {
	expectedGroups = ""
	failOnGroupMismatch = true
	t.Cleanup(func() { failOnGroupMismatch = false })

	err := checkExitCode(nil)
	if err == nil || err.Error() == "" {
		t.Fatal("expected an error when --fail-on-group-mismatch is set without --expected-groups")
	}
}

func TestJUnitOptions(t *testing.T) {
	tests := []struct {
		name       string
		groups     string
		mode       string
		requirePQC bool
		wantGroups []string
		wantErr    bool
	}{
		{name: "no gates configured"},
		{name: "pqc only", requirePQC: true},
		{name: "groups", groups: "X25519MLKEM768,X25519", mode: "exact", wantGroups: []string{"X25519MLKEM768", "X25519"}},
		{name: "separators only", groups: ",", mode: "contains", wantErr: true},
		{name: "invalid mode", groups: "X25519", mode: "subset", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectedGroups, groupsMode, requirePQC = tc.groups, tc.mode, tc.requirePQC
			t.Cleanup(func() { expectedGroups, groupsMode, requirePQC = "", "contains", false })

			opts, err := junitOptions()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.RequirePQC != tc.requirePQC {
				t.Errorf("RequirePQC = %v, want %v", opts.RequirePQC, tc.requirePQC)
			}
			if len(opts.ExpectedGroups) != len(tc.wantGroups) {
				t.Fatalf("ExpectedGroups = %v, want %v", opts.ExpectedGroups, tc.wantGroups)
			}
			for i := range tc.wantGroups {
				if opts.ExpectedGroups[i] != tc.wantGroups[i] {
					t.Errorf("ExpectedGroups[%d] = %q, want %q", i, opts.ExpectedGroups[i], tc.wantGroups[i])
				}
			}
		})
	}
}
