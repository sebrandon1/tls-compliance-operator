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
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestRequirePQCFlagRegistered(t *testing.T) {
	cmd := newRootCmd()

	f := cmd.PersistentFlags().Lookup("require-pqc")
	if f == nil {
		t.Fatal("expected persistent flag \"require-pqc\"")
	}
	if f.DefValue != "false" {
		t.Errorf("expected default false, got %s", f.DefValue)
	}
}

func TestCheckExitCode_RequirePQC(t *testing.T) {
	tests := []struct {
		name     string
		reports  []securityv1alpha1.TLSComplianceReport
		wantExit bool
	}{
		{
			name: "all PQCReady passes",
			reports: []securityv1alpha1.TLSComplianceReport{
				{Status: securityv1alpha1.TLSComplianceReportStatus{
					ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
					PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
				}},
			},
			wantExit: false,
		},
		{
			name: "TLS13Capable fails",
			reports: []securityv1alpha1.TLSComplianceReport{
				{Status: securityv1alpha1.TLSComplianceReportStatus{
					ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
					PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
				}},
			},
			wantExit: true,
		},
		{
			name: "unscannable endpoints are skipped",
			reports: []securityv1alpha1.TLSComplianceReport{
				{Status: securityv1alpha1.TLSComplianceReportStatus{
					ComplianceStatus: securityv1alpha1.ComplianceStatusTimeout,
				}},
				{Status: securityv1alpha1.TLSComplianceReportStatus{
					ComplianceStatus: securityv1alpha1.ComplianceStatusUnreachable,
				}},
			},
			wantExit: false,
		},
		{
			name: "non-compliant but PQCReady passes the PQC gate",
			reports: []securityv1alpha1.TLSComplianceReport{
				{Status: securityv1alpha1.TLSComplianceReportStatus{
					ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
					PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
				}},
			},
			wantExit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requirePQC = true
			defer func() { requirePQC = false }()

			err := checkExitCode(tc.reports)

			var ece exitCodeError
			gotExit := errors.As(err, &ece)
			if gotExit != tc.wantExit {
				t.Fatalf("checkExitCode() error = %v, wantExit %v", err, tc.wantExit)
			}
			if gotExit && ece.code != 1 {
				t.Errorf("exit code = %d, want 1", ece.code)
			}
		})
	}
}

func TestCheckExitCode_RequirePQC_DisabledIgnoresReadiness(t *testing.T) {
	requirePQC = false

	reports := []securityv1alpha1.TLSComplianceReport{
		{Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			PQCReadiness:     securityv1alpha1.PQCReadinessLegacyTLS,
		}},
	}
	if err := checkExitCode(reports); err != nil {
		t.Errorf("expected nil error when --require-pqc is off, got %v", err)
	}
}
