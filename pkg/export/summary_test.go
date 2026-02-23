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
	if s.CompliancePercent != 50 {
		t.Errorf("expected 50%% compliance, got %f", s.CompliancePercent)
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

func TestWriteSummary_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSummary(&buf, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Total Endpoints:") {
		t.Error("expected output to contain 'Total Endpoints:'")
	}
	if !strings.Contains(output, "0.0%") {
		t.Error("expected 0.0% compliance rate")
	}
}
