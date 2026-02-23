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

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func testReports() []securityv1alpha1.TLSComplianceReport {
	return []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "svc1.default",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "default",
				SourceName:      "svc1",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "ing1.kube-system",
				Port:            8443,
				SourceKind:      securityv1alpha1.SourceKindIngress,
				SourceNamespace: "kube-system",
				SourceName:      "ing1",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "route1.default",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindRoute,
				SourceNamespace: "default",
				SourceName:      "route1",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}
}

func TestFilterReports_EmptyFilters(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{})

	if len(filtered) != len(reports) {
		t.Errorf("expected %d reports, got %d", len(reports), len(filtered))
	}
}

func TestFilterReports_ByNamespace(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{Namespace: "default"})

	if len(filtered) != 2 {
		t.Fatalf("expected 2 reports in default namespace, got %d", len(filtered))
	}
	for _, r := range filtered {
		if r.Spec.SourceNamespace != "default" {
			t.Errorf("expected namespace default, got %s", r.Spec.SourceNamespace)
		}
	}
}

func TestFilterReports_ByStatus(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{Status: "NonCompliant"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 NonCompliant report, got %d", len(filtered))
	}
	if filtered[0].Spec.SourceName != "ing1" {
		t.Errorf("expected ing1, got %s", filtered[0].Spec.SourceName)
	}
}

func TestFilterReports_ByStatusCaseInsensitive(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{Status: "noncompliant"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
}

func TestFilterReports_BySource(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{Source: "Service"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 Service report, got %d", len(filtered))
	}
	if filtered[0].Spec.SourceKind != securityv1alpha1.SourceKindService {
		t.Errorf("expected Service, got %s", filtered[0].Spec.SourceKind)
	}
}

func TestFilterReports_BySourceCaseInsensitive(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{Source: "service"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
}

func TestFilterReports_CombinedFilters(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{
		Namespace: "default",
		Status:    "Compliant",
	})

	if len(filtered) != 2 {
		t.Fatalf("expected 2 compliant reports in default, got %d", len(filtered))
	}
}

func TestFilterReports_CombinedFiltersAllThree(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{
		Namespace: "default",
		Status:    "Compliant",
		Source:    "Route",
	})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
	if filtered[0].Spec.SourceName != "route1" {
		t.Errorf("expected route1, got %s", filtered[0].Spec.SourceName)
	}
}

func TestFilterReports_NoMatch(t *testing.T) {
	reports := testReports()
	filtered := FilterReports(reports, FilterOptions{Namespace: "nonexistent"})

	if len(filtered) != 0 {
		t.Errorf("expected 0 reports, got %d", len(filtered))
	}
}

func TestFilterReports_NilInput(t *testing.T) {
	filtered := FilterReports(nil, FilterOptions{Namespace: "default"})

	if len(filtered) != 0 {
		t.Errorf("expected 0 reports, got %d", len(filtered))
	}
}
