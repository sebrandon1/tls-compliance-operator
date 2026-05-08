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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func sortTestReports() []securityv1alpha1.TLSComplianceReport {
	exp1 := metav1.NewTime(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	exp2 := metav1.NewTime(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))

	return []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "charlie.test", Port: 8443},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusNonCompliant,
				OverallCipherGrade: "C",
				PQCReadiness:       securityv1alpha1.PQCReadinessLegacyTLS,
				CertificateInfo:    &securityv1alpha1.CertificateInfo{NotAfter: &exp2},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "alpha.test", Port: 443},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusCompliant,
				OverallCipherGrade: "A",
				PQCReadiness:       securityv1alpha1.PQCReadinessPQCReady,
				CertificateInfo:    &securityv1alpha1.CertificateInfo{NotAfter: &exp1},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "bravo.test", Port: 443},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusCompliant,
				OverallCipherGrade: "B",
				PQCReadiness:       securityv1alpha1.PQCReadinessTLS13Capable,
			},
		},
	}
}

func TestSortReports_ByHost(t *testing.T) {
	reports := sortTestReports()
	SortReports(reports, "host")

	if reports[0].Spec.Host != "alpha.test" {
		t.Errorf("expected alpha.test first, got %s", reports[0].Spec.Host)
	}
	if reports[1].Spec.Host != "bravo.test" {
		t.Errorf("expected bravo.test second, got %s", reports[1].Spec.Host)
	}
	if reports[2].Spec.Host != "charlie.test" {
		t.Errorf("expected charlie.test third, got %s", reports[2].Spec.Host)
	}
}

func TestSortReports_ByPort(t *testing.T) {
	reports := sortTestReports()
	SortReports(reports, "port")

	if reports[0].Spec.Port != 443 {
		t.Errorf("expected port 443 first, got %d", reports[0].Spec.Port)
	}
	if reports[2].Spec.Port != 8443 {
		t.Errorf("expected port 8443 last, got %d", reports[2].Spec.Port)
	}
}

func TestSortReports_ByCompliance(t *testing.T) {
	reports := sortTestReports()
	SortReports(reports, "compliance")

	if reports[0].Status.ComplianceStatus != securityv1alpha1.ComplianceStatusCompliant {
		t.Errorf("expected Compliant first, got %s", reports[0].Status.ComplianceStatus)
	}
	if reports[2].Status.ComplianceStatus != securityv1alpha1.ComplianceStatusNonCompliant {
		t.Errorf("expected NonCompliant last, got %s", reports[2].Status.ComplianceStatus)
	}
}

func TestSortReports_ByExpiry(t *testing.T) {
	reports := sortTestReports()
	SortReports(reports, "expiry")

	if reports[0].Spec.Host != "alpha.test" {
		t.Errorf("expected alpha.test (earliest expiry) first, got %s", reports[0].Spec.Host)
	}
	if reports[1].Spec.Host != "charlie.test" {
		t.Errorf("expected charlie.test second, got %s", reports[1].Spec.Host)
	}
	if reports[2].Spec.Host != "bravo.test" {
		t.Errorf("expected bravo.test (no cert, sorts last) third, got %s", reports[2].Spec.Host)
	}
}

func TestSortReports_ByGrade(t *testing.T) {
	reports := sortTestReports()
	SortReports(reports, "grade")

	if reports[0].Status.OverallCipherGrade != "A" {
		t.Errorf("expected grade A first, got %s", reports[0].Status.OverallCipherGrade)
	}
	if reports[2].Status.OverallCipherGrade != "C" {
		t.Errorf("expected grade C last, got %s", reports[2].Status.OverallCipherGrade)
	}
}

func TestSortReports_ByPQC(t *testing.T) {
	reports := sortTestReports()
	SortReports(reports, "pqc")

	if reports[0].Status.PQCReadiness != securityv1alpha1.PQCReadinessLegacyTLS {
		t.Errorf("expected LegacyTLS first, got %s", reports[0].Status.PQCReadiness)
	}
	if reports[2].Status.PQCReadiness != securityv1alpha1.PQCReadinessTLS13Capable {
		t.Errorf("expected TLS13Capable last, got %s", reports[2].Status.PQCReadiness)
	}
}

func TestSortReports_EmptyKey(t *testing.T) {
	reports := sortTestReports()
	original := reports[0].Spec.Host

	SortReports(reports, "")

	if reports[0].Spec.Host != original {
		t.Error("empty sort key should be a no-op")
	}
}

func TestSortReports_UnknownKey(t *testing.T) {
	reports := sortTestReports()
	original := reports[0].Spec.Host

	SortReports(reports, "nonexistent")

	if reports[0].Spec.Host != original {
		t.Error("unknown sort key should be a no-op")
	}
}

func TestSortReports_CaseInsensitiveKey(t *testing.T) {
	reports := sortTestReports()
	SortReports(reports, "HOST")

	if reports[0].Spec.Host != "alpha.test" {
		t.Errorf("expected alpha.test first with uppercase HOST key, got %s", reports[0].Spec.Host)
	}
}

func TestSortReports_EmptyGradeSortsLast(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "no-grade.test"},
			Status: securityv1alpha1.TLSComplianceReportStatus{OverallCipherGrade: ""},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "grade-b.test"},
			Status: securityv1alpha1.TLSComplianceReportStatus{OverallCipherGrade: "B"},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "grade-a.test"},
			Status: securityv1alpha1.TLSComplianceReportStatus{OverallCipherGrade: "A"},
		},
	}

	SortReports(reports, "grade")

	if reports[0].Status.OverallCipherGrade != "A" {
		t.Errorf("expected grade A first, got %q", reports[0].Status.OverallCipherGrade)
	}
	if reports[1].Status.OverallCipherGrade != "B" {
		t.Errorf("expected grade B second, got %q", reports[1].Status.OverallCipherGrade)
	}
	if reports[2].Status.OverallCipherGrade != "" {
		t.Errorf("expected empty grade last, got %q", reports[2].Status.OverallCipherGrade)
	}
}

func TestSortReports_CompliancePriority(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "unreachable.test"},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusUnreachable},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "compliant.test"},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "noncompliant.test"},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "notls.test"},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS},
		},
	}

	SortReports(reports, "compliance")

	expected := []securityv1alpha1.ComplianceStatus{
		securityv1alpha1.ComplianceStatusCompliant,
		securityv1alpha1.ComplianceStatusNonCompliant,
		securityv1alpha1.ComplianceStatusNoTLS,
		securityv1alpha1.ComplianceStatusUnreachable,
	}

	for i, want := range expected {
		if reports[i].Status.ComplianceStatus != want {
			t.Errorf("position %d: expected %s, got %s", i, want, reports[i].Status.ComplianceStatus)
		}
	}
}
