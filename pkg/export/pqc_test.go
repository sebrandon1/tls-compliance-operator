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

package export

import (
	"strings"
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func makePQCReport(host string, port int32, status securityv1alpha1.ComplianceStatus, readiness securityv1alpha1.PQCReadiness) securityv1alpha1.TLSComplianceReport {
	return securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: host,
			Port: port,
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: status,
			PQCReadiness:     readiness,
		},
	}
}

func TestEvaluatePQCGate_ReadinessMatrix(t *testing.T) {
	tests := []struct {
		name      string
		report    securityv1alpha1.TLSComplianceReport
		wantReady int
		wantNot   int
		wantSkip  int
		wantPass  bool
	}{
		{
			name:      "PQCReady passes",
			report:    makePQCReport("a", 443, securityv1alpha1.ComplianceStatusCompliant, securityv1alpha1.PQCReadinessPQCReady),
			wantReady: 1,
			wantPass:  true,
		},
		{
			name:     "TLS13Capable fails",
			report:   makePQCReport("a", 443, securityv1alpha1.ComplianceStatusCompliant, securityv1alpha1.PQCReadinessTLS13Capable),
			wantNot:  1,
			wantPass: false,
		},
		{
			name:     "LegacyTLS fails",
			report:   makePQCReport("a", 443, securityv1alpha1.ComplianceStatusNonCompliant, securityv1alpha1.PQCReadinessLegacyTLS),
			wantNot:  1,
			wantPass: false,
		},
		{
			name:     "empty readiness fails rather than silently passing",
			report:   makePQCReport("a", 443, securityv1alpha1.ComplianceStatusCompliant, ""),
			wantNot:  1,
			wantPass: false,
		},
		{
			name:     "NoPQC is skipped",
			report:   makePQCReport("a", 443, securityv1alpha1.ComplianceStatusNoTLS, securityv1alpha1.PQCReadinessNoPQC),
			wantSkip: 1,
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluatePQCGate([]securityv1alpha1.TLSComplianceReport{tc.report})
			if got.Ready != tc.wantReady || got.NotReady != tc.wantNot || got.Skipped != tc.wantSkip {
				t.Errorf("counts = ready %d / not ready %d / skipped %d, want %d / %d / %d",
					got.Ready, got.NotReady, got.Skipped, tc.wantReady, tc.wantNot, tc.wantSkip)
			}
			if got.Passed() != tc.wantPass {
				t.Errorf("Passed() = %v, want %v", got.Passed(), tc.wantPass)
			}
		})
	}
}

func TestEvaluatePQCGate_UnscannableStatusesAreSkipped(t *testing.T) {
	statuses := []securityv1alpha1.ComplianceStatus{
		securityv1alpha1.ComplianceStatusTimeout,
		securityv1alpha1.ComplianceStatusUnreachable,
		securityv1alpha1.ComplianceStatusClosed,
		securityv1alpha1.ComplianceStatusFiltered,
		securityv1alpha1.ComplianceStatusLocalhostOnly,
		securityv1alpha1.ComplianceStatusMutualTLSRequired,
		securityv1alpha1.ComplianceStatusPending,
		securityv1alpha1.ComplianceStatusUnknown,
		securityv1alpha1.ComplianceStatusPlaintextHTTP,
	}

	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			// Even with a readiness that would otherwise fail, an unscannable
			// endpoint is skipped rather than counted as not ready.
			report := makePQCReport("a", 443, status, securityv1alpha1.PQCReadinessLegacyTLS)
			got := EvaluatePQCGate([]securityv1alpha1.TLSComplianceReport{report})

			if got.Skipped != 1 || got.NotReady != 0 || got.Ready != 0 {
				t.Errorf("counts = ready %d / not ready %d / skipped %d, want 0 / 0 / 1",
					got.Ready, got.NotReady, got.Skipped)
			}
			if !got.Passed() {
				t.Error("Passed() = false, want true: unscannable endpoints must not fail the gate")
			}
			if len(got.SkippedReports) != 1 || !strings.Contains(got.SkippedReports[0], "a:443") {
				t.Errorf("SkippedReports = %v, want one entry naming a:443", got.SkippedReports)
			}
		})
	}
}

func TestEvaluatePQCGate_MixedReports(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		makePQCReport("ready.example.com", 443, securityv1alpha1.ComplianceStatusCompliant, securityv1alpha1.PQCReadinessPQCReady),
		makePQCReport("legacy.example.com", 8443, securityv1alpha1.ComplianceStatusNonCompliant, securityv1alpha1.PQCReadinessLegacyTLS),
		makePQCReport("tls13.example.com", 9443, securityv1alpha1.ComplianceStatusCompliant, securityv1alpha1.PQCReadinessTLS13Capable),
		makePQCReport("down.example.com", 443, securityv1alpha1.ComplianceStatusTimeout, ""),
	}

	got := EvaluatePQCGate(reports)

	if got.Ready != 1 || got.NotReady != 2 || got.Skipped != 1 {
		t.Fatalf("counts = ready %d / not ready %d / skipped %d, want 1 / 2 / 1",
			got.Ready, got.NotReady, got.Skipped)
	}
	if got.Passed() {
		t.Error("Passed() = true, want false with not-ready endpoints")
	}

	wantNotReady := []string{"legacy.example.com:8443 (LegacyTLS)", "tls13.example.com:9443 (TLS13Capable)"}
	if len(got.NotReadyReports) != len(wantNotReady) {
		t.Fatalf("NotReadyReports = %v, want %v", got.NotReadyReports, wantNotReady)
	}
	for i := range wantNotReady {
		if got.NotReadyReports[i] != wantNotReady[i] {
			t.Errorf("NotReadyReports[%d] = %q, want %q", i, got.NotReadyReports[i], wantNotReady[i])
		}
	}
}

func TestEvaluatePQCGate_Empty(t *testing.T) {
	got := EvaluatePQCGate(nil)
	if !got.Passed() {
		t.Error("Passed() = false for an empty report set, want true")
	}
	if got.Ready != 0 || got.NotReady != 0 || got.Skipped != 0 {
		t.Errorf("counts = %d/%d/%d, want all zero", got.Ready, got.NotReady, got.Skipped)
	}
}

func TestWritePQCGate(t *testing.T) {
	result := PQCGateResult{
		Ready:           2,
		NotReady:        1,
		Skipped:         1,
		NotReadyReports: []string{"legacy.example.com:8443 (LegacyTLS)"},
		SkippedReports:  []string{"down.example.com:443 (Timeout)"},
	}

	var sb strings.Builder
	if err := WritePQCGate(&sb, result); err != nil {
		t.Fatalf("WritePQCGate() error = %v", err)
	}

	out := sb.String()
	for _, want := range []string{
		"PQC Gate",
		"Ready:\t2",
		"Not Ready:\t1",
		"Skipped:\t1",
		"legacy.example.com:8443 (LegacyTLS)",
		"down.example.com:443 (Timeout)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWritePQCGate_AllReadyOmitsEndpointLists(t *testing.T) {
	var sb strings.Builder
	if err := WritePQCGate(&sb, PQCGateResult{Ready: 3}); err != nil {
		t.Fatalf("WritePQCGate() error = %v", err)
	}

	out := sb.String()
	if strings.Contains(out, "Not PQC-ready endpoints") {
		t.Errorf("output should omit the not-ready list when empty:\n%s", out)
	}
	if strings.Contains(out, "Skipped (unscannable) endpoints") {
		t.Errorf("output should omit the skipped list when empty:\n%s", out)
	}
	if !strings.Contains(out, "Ready:\t3") {
		t.Errorf("output missing ready count:\n%s", out)
	}
}
