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
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestComputeSummary_Empty(t *testing.T) {
	s := ComputeSummary(nil, time.Now())

	if s.Total != 0 {
		t.Errorf("expected Total 0, got %d", s.Total)
	}
	if s.TLSCapable != 0 {
		t.Errorf("expected TLSCapable 0, got %d", s.TLSCapable)
	}
	if s.CompliancePercent != 0 {
		t.Errorf("expected CompliancePercent 0, got %f", s.CompliancePercent)
	}
}

func TestComputeSummary_AllCompliant(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	s := ComputeSummary(reports, time.Now())

	if s.Total != 2 {
		t.Errorf("expected Total 2, got %d", s.Total)
	}
	if s.TLSCapable != 2 {
		t.Errorf("expected TLSCapable 2, got %d", s.TLSCapable)
	}
	if s.CompliancePercent != 100 {
		t.Errorf("expected 100%% compliance, got %f", s.CompliancePercent)
	}
	if s.ByStatus[securityv1alpha1.ComplianceStatusCompliant] != 2 {
		t.Errorf("expected 2 compliant, got %d", s.ByStatus[securityv1alpha1.ComplianceStatusCompliant])
	}
	if s.BySourceKind[securityv1alpha1.SourceKindService] != 2 {
		t.Errorf("expected 2 services, got %d", s.BySourceKind[securityv1alpha1.SourceKindService])
	}
}

func TestComputeSummary_MixedStatuses(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				SourceKind: securityv1alpha1.SourceKindIngress,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				SourceKind: securityv1alpha1.SourceKindRoute,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusUnreachable,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	s := ComputeSummary(reports, time.Now())

	if s.Total != 4 {
		t.Errorf("expected Total 4, got %d", s.Total)
	}
	if s.TLSCapable != 3 {
		t.Errorf("expected TLSCapable 3, got %d", s.TLSCapable)
	}
	expected := float64(2) / float64(3) * 100
	if math.Abs(s.CompliancePercent-expected) > 0.01 {
		t.Errorf("expected ~%.2f%% compliance, got %f", expected, s.CompliancePercent)
	}
	if s.ByStatus[securityv1alpha1.ComplianceStatusCompliant] != 2 {
		t.Errorf("expected 2 compliant, got %d", s.ByStatus[securityv1alpha1.ComplianceStatusCompliant])
	}
	if s.ByStatus[securityv1alpha1.ComplianceStatusNonCompliant] != 1 {
		t.Errorf("expected 1 non-compliant, got %d", s.ByStatus[securityv1alpha1.ComplianceStatusNonCompliant])
	}
	if s.BySourceKind[securityv1alpha1.SourceKindService] != 2 {
		t.Errorf("expected 2 services, got %d", s.BySourceKind[securityv1alpha1.SourceKindService])
	}
	if s.BySourceKind[securityv1alpha1.SourceKindIngress] != 1 {
		t.Errorf("expected 1 ingress, got %d", s.BySourceKind[securityv1alpha1.SourceKindIngress])
	}
}

func TestComputeSummary_CertExpiry(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)

	expired := metav1.NewTime(now.Add(-24 * time.Hour))           // yesterday
	expiring3d := metav1.NewTime(now.Add(3 * 24 * time.Hour))     // 3 days
	expiring20d := metav1.NewTime(now.Add(20 * 24 * time.Hour))   // 20 days
	expiring60d := metav1.NewTime(now.Add(60 * 24 * time.Hour))   // 60 days
	expiring120d := metav1.NewTime(now.Add(120 * 24 * time.Hour)) // 120 days (not in any bucket)

	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo:  &securityv1alpha1.CertificateInfo{NotAfter: &expired},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo:  &securityv1alpha1.CertificateInfo{NotAfter: &expiring3d},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo:  &securityv1alpha1.CertificateInfo{NotAfter: &expiring20d},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo:  &securityv1alpha1.CertificateInfo{NotAfter: &expiring60d},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo:  &securityv1alpha1.CertificateInfo{NotAfter: &expiring120d},
			},
		},
	}

	s := ComputeSummary(reports, now)

	if s.CertExpired != 1 {
		t.Errorf("expected 1 expired cert, got %d", s.CertExpired)
	}
	if s.CertExpiring7d != 1 {
		t.Errorf("expected 1 cert expiring < 7d, got %d", s.CertExpiring7d)
	}
	if s.CertExpiring30d != 1 {
		t.Errorf("expected 1 cert expiring < 30d, got %d", s.CertExpiring30d)
	}
	if s.CertExpiring90d != 1 {
		t.Errorf("expected 1 cert expiring < 90d, got %d", s.CertExpiring90d)
	}
}

func TestComputeSummary_NoCertInfo(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS,
			},
		},
	}

	s := ComputeSummary(reports, time.Now())

	if s.CertExpired != 0 || s.CertExpiring7d != 0 || s.CertExpiring30d != 0 || s.CertExpiring90d != 0 {
		t.Error("expected no cert expiry counts for reports without cert info")
	}
}

func TestComputeSummary_PQCReadiness(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
				MLKEMSupported:   true,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessLegacyTLS,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS,
				PQCReadiness:     securityv1alpha1.PQCReadinessNoPQC,
			},
		},
	}

	s := ComputeSummary(reports, time.Now())

	if s.ByPQCReadiness[securityv1alpha1.PQCReadinessPQCReady] != 1 {
		t.Errorf("expected 1 PQCReady, got %d", s.ByPQCReadiness[securityv1alpha1.PQCReadinessPQCReady])
	}
	if s.ByPQCReadiness[securityv1alpha1.PQCReadinessTLS13Capable] != 1 {
		t.Errorf("expected 1 TLS13Capable, got %d", s.ByPQCReadiness[securityv1alpha1.PQCReadinessTLS13Capable])
	}
	if s.ByPQCReadiness[securityv1alpha1.PQCReadinessLegacyTLS] != 1 {
		t.Errorf("expected 1 LegacyTLS, got %d", s.ByPQCReadiness[securityv1alpha1.PQCReadinessLegacyTLS])
	}
	if s.ByPQCReadiness[securityv1alpha1.PQCReadinessNoPQC] != 1 {
		t.Errorf("expected 1 NoPQC, got %d", s.ByPQCReadiness[securityv1alpha1.PQCReadinessNoPQC])
	}
	expectedPQC := float64(1) / float64(3) * 100
	if math.Abs(s.PQCReadyPercent-expectedPQC) > 0.01 {
		t.Errorf("expected ~%.2f%% PQC ready, got %f", expectedPQC, s.PQCReadyPercent)
	}
	if s.MLKEMProbeCount != 1 {
		t.Errorf("expected 1 MLKEM probe count, got %d", s.MLKEMProbeCount)
	}
}

func TestWriteSummary_Output(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindIngress},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Total Endpoints:") {
		t.Error("expected output to contain 'Total Endpoints:'")
	}
	if !strings.Contains(output, "TLS-Capable Endpoints:") {
		t.Error("expected output to contain 'TLS-Capable Endpoints:'")
	}
	if !strings.Contains(output, "Compliance Rate:") {
		t.Error("expected output to contain 'Compliance Rate:'")
	}
	if !strings.Contains(output, "Compliant:") {
		t.Error("expected output to contain 'Compliant:'")
	}
	if !strings.Contains(output, "NonCompliant:") {
		t.Error("expected output to contain 'NonCompliant:'")
	}
	if !strings.Contains(output, "Service:") {
		t.Error("expected output to contain 'Service:'")
	}
	if !strings.Contains(output, "Ingress:") {
		t.Error("expected output to contain 'Ingress:'")
	}
}

func TestWriteSummary_PQCSection(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
				MLKEMSupported:   true,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Post-Quantum Cryptography Readiness") {
		t.Error("expected output to contain PQC readiness section")
	}
	if !strings.Contains(output, "PQC Ready Rate:") {
		t.Error("expected output to contain 'PQC Ready Rate:'")
	}
	if !strings.Contains(output, "PQCReady:") {
		t.Error("expected output to contain 'PQCReady:'")
	}
	if !strings.Contains(output, "TLS13Capable:") {
		t.Error("expected output to contain 'TLS13Capable:'")
	}
	if !strings.Contains(output, "ML-KEM Supported (active probe):") {
		t.Error("expected output to contain 'ML-KEM Supported (active probe):'")
	}
}

func TestWriteSummary_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSummary(&buf, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Total Endpoints:") {
		t.Error("expected output to contain 'Total Endpoints:'")
	}
	if !strings.Contains(output, "TLS-Capable Endpoints:") {
		t.Error("expected output to contain 'TLS-Capable Endpoints:'")
	}
	if !strings.Contains(output, "0.0%") {
		t.Error("expected 0.0% compliance rate")
	}
}

func TestComputeSummary_CertExpiryBoundaries(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	makeReport := func(daysFromNow int) securityv1alpha1.TLSComplianceReport {
		expiry := metav1.NewTime(now.AddDate(0, 0, daysFromNow))
		return securityv1alpha1.TLSComplianceReport{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "test.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo: &securityv1alpha1.CertificateInfo{
					NotAfter: &expiry,
				},
			},
		}
	}

	tests := []struct {
		name            string
		daysFromNow     int
		wantExpired     int
		wantExpiring7d  int
		wantExpiring30d int
		wantExpiring90d int
	}{
		{"expired yesterday", -1, 1, 0, 0, 0},
		{"expires today", 0, 0, 1, 0, 0},
		{"expires in 1 day", 1, 0, 1, 0, 0},
		{"expires in 6 days", 6, 0, 1, 0, 0},
		{"expires in 8 days", 8, 0, 0, 1, 0},
		{"expires in 29 days", 29, 0, 0, 1, 0},
		{"expires in 31 days", 31, 0, 0, 0, 1},
		{"expires in 89 days", 89, 0, 0, 0, 1},
		{"expires in 91 days", 91, 0, 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reports := []securityv1alpha1.TLSComplianceReport{makeReport(tt.daysFromNow)}
			summary := ComputeSummary(reports, now)

			if summary.CertExpired != tt.wantExpired {
				t.Errorf("CertExpired: got %d, want %d", summary.CertExpired, tt.wantExpired)
			}
			if summary.CertExpiring7d != tt.wantExpiring7d {
				t.Errorf("CertExpiring7d: got %d, want %d", summary.CertExpiring7d, tt.wantExpiring7d)
			}
			if summary.CertExpiring30d != tt.wantExpiring30d {
				t.Errorf("CertExpiring30d: got %d, want %d", summary.CertExpiring30d, tt.wantExpiring30d)
			}
			if summary.CertExpiring90d != tt.wantExpiring90d {
				t.Errorf("CertExpiring90d: got %d, want %d", summary.CertExpiring90d, tt.wantExpiring90d)
			}
		})
	}
}

func TestComputeSummary_FIPSDetected(t *testing.T) {
	now := time.Now()
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
				FIPSDetected:     true,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
				FIPSDetected:     true,
			},
		},
	}

	s := ComputeSummary(reports, now)
	if !s.FIPSDetected {
		t.Error("expected FIPSDetected to be true")
	}
}

func TestComputeSummary_FIPSNotDetected(t *testing.T) {
	now := time.Now()
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
			},
		},
	}

	s := ComputeSummary(reports, now)
	if s.FIPSDetected {
		t.Error("expected FIPSDetected to be false")
	}
}

func TestWriteSummary_FIPSLine(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
				FIPSDetected:     true,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "FIPS Mode:") {
		t.Error("expected output to contain 'FIPS Mode:'")
	}
	if !strings.Contains(output, "ML-KEM key exchange unavailable") {
		t.Error("expected output to contain 'ML-KEM key exchange unavailable'")
	}
}

func TestWriteSummary_NoFIPSLine(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "FIPS Mode:") {
		t.Error("expected output to NOT contain 'FIPS Mode:' when FIPS is not detected")
	}
}

func TestComputeSummary_FIPSMixedReports(t *testing.T) {
	now := time.Now()
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
				FIPSDetected:     false,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
				FIPSDetected:     true,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessTLS13Capable,
				FIPSDetected:     false,
			},
		},
	}

	s := ComputeSummary(reports, now)
	if !s.FIPSDetected {
		t.Error("expected FIPSDetected to be true when at least one report has FIPSDetected=true")
	}
}

func TestComputeSummary_TLSAdherence(t *testing.T) {
	now := time.Now()
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				TLSAdherence:     "StrictAllComponents",
			},
		},
	}

	s := ComputeSummary(reports, now)
	if s.TLSAdherence != "StrictAllComponents" {
		t.Errorf("expected TLSAdherence=StrictAllComponents, got %q", s.TLSAdherence)
	}
}

func TestComputeSummary_TLSAdherenceEmpty(t *testing.T) {
	now := time.Now()
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	s := ComputeSummary(reports, now)
	if s.TLSAdherence != "" {
		t.Errorf("expected empty TLSAdherence, got %q", s.TLSAdherence)
	}
}

func TestWriteSummary_TLSAdherenceLine(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				TLSAdherence:     "StrictAllComponents",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "TLS Security Profile") {
		t.Error("expected output to contain 'TLS Security Profile' section")
	}
	if !strings.Contains(output, "TLS Adherence:") {
		t.Error("expected output to contain 'TLS Adherence:'")
	}
	if !strings.Contains(output, "StrictAllComponents") {
		t.Error("expected output to contain 'StrictAllComponents'")
	}
}

func TestWriteSummary_NoAdherenceLine(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "TLS Security Profile") {
		t.Error("expected output to NOT contain 'TLS Security Profile' when adherence is empty")
	}
}

func TestComputeSummary_GatewayAPISourceKinds(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindHTTPRoute},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindTLSRoute},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindGateway},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant}},
	}

	s := ComputeSummary(reports, time.Now())
	if s.BySourceKind[securityv1alpha1.SourceKindHTTPRoute] != 1 {
		t.Errorf("expected 1 HTTPRoute, got %d", s.BySourceKind[securityv1alpha1.SourceKindHTTPRoute])
	}
	if s.BySourceKind[securityv1alpha1.SourceKindTLSRoute] != 1 {
		t.Errorf("expected 1 TLSRoute, got %d", s.BySourceKind[securityv1alpha1.SourceKindTLSRoute])
	}
	if s.BySourceKind[securityv1alpha1.SourceKindGateway] != 1 {
		t.Errorf("expected 1 Gateway, got %d", s.BySourceKind[securityv1alpha1.SourceKindGateway])
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	for _, kind := range []string{"HTTPRoute:", "TLSRoute:", "Gateway:"} {
		if !strings.Contains(output, kind) {
			t.Errorf("expected output to contain %q", kind)
		}
	}
}

func TestComputeSummary_AllNonTLS(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusPlaintextHTTP},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusClosed},
		},
	}

	s := ComputeSummary(reports, time.Now())
	if s.Total != 3 {
		t.Errorf("expected Total 3, got %d", s.Total)
	}
	if s.TLSCapable != 0 {
		t.Errorf("expected TLSCapable 0, got %d", s.TLSCapable)
	}
	if s.CompliancePercent != 0 {
		t.Errorf("expected 0%% compliance, got %f", s.CompliancePercent)
	}
	if s.ForwardSecrecyPercent != 0 {
		t.Errorf("expected 0%% forward secrecy, got %f", s.ForwardSecrecyPercent)
	}
	if s.PQCReadyPercent != 0 {
		t.Errorf("expected 0%% PQC ready, got %f", s.PQCReadyPercent)
	}
}

func TestWriteSummary_AllNonTLS_SuppressesForwardSecrecy(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusClosed},
		},
	}

	var buf bytes.Buffer
	if err := WriteSummary(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Total Endpoints:") {
		t.Error("expected output to contain 'Total Endpoints:'")
	}
	if strings.Contains(output, "Forward Secrecy:") {
		t.Error("expected output to NOT contain 'Forward Secrecy:' when no TLS-capable endpoints exist")
	}
}

func TestComputeSummary_TLSCapableMix(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				ForwardSecrecy:   true,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusWarning,
				ForwardSecrecy:   true,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusMutualTLSRequired,
			},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusTimeout},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusPending},
		},
	}

	s := ComputeSummary(reports, time.Now())
	if s.Total != 7 {
		t.Errorf("expected Total 7, got %d", s.Total)
	}
	if s.TLSCapable != 4 {
		t.Errorf("expected TLSCapable 4, got %d", s.TLSCapable)
	}
	if s.CompliancePercent != 25 {
		t.Errorf("expected 25%% compliance, got %f", s.CompliancePercent)
	}
	if s.ForwardSecrecyPercent != 50 {
		t.Errorf("expected 50%% forward secrecy, got %f", s.ForwardSecrecyPercent)
	}
}
