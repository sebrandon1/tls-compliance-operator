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
	filtered, _ := FilterReports(reports, FilterOptions{})

	if len(filtered) != len(reports) {
		t.Errorf("expected %d reports, got %d", len(reports), len(filtered))
	}
}

func TestFilterReports_ByNamespace(t *testing.T) {
	reports := testReports()
	filtered, _ := FilterReports(reports, FilterOptions{Namespace: "default"})

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
	filtered, _ := FilterReports(reports, FilterOptions{Status: "NonCompliant"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 NonCompliant report, got %d", len(filtered))
	}
	if filtered[0].Spec.SourceName != "ing1" {
		t.Errorf("expected ing1, got %s", filtered[0].Spec.SourceName)
	}
}

func TestFilterReports_ByStatusCaseInsensitive(t *testing.T) {
	reports := testReports()
	filtered, _ := FilterReports(reports, FilterOptions{Status: "noncompliant"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
}

func TestFilterReports_BySource(t *testing.T) {
	reports := testReports()
	filtered, _ := FilterReports(reports, FilterOptions{Source: "Service"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 Service report, got %d", len(filtered))
	}
	if filtered[0].Spec.SourceKind != securityv1alpha1.SourceKindService {
		t.Errorf("expected Service, got %s", filtered[0].Spec.SourceKind)
	}
}

func TestFilterReports_BySourceCaseInsensitive(t *testing.T) {
	reports := testReports()
	filtered, _ := FilterReports(reports, FilterOptions{Source: "service"})

	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
}

func TestFilterReports_CombinedFilters(t *testing.T) {
	reports := testReports()
	filtered, _ := FilterReports(reports, FilterOptions{
		Namespace: "default",
		Status:    "Compliant",
	})

	if len(filtered) != 2 {
		t.Fatalf("expected 2 compliant reports in default, got %d", len(filtered))
	}
}

func TestFilterReports_CombinedFiltersAllThree(t *testing.T) {
	reports := testReports()
	filtered, _ := FilterReports(reports, FilterOptions{
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
	filtered, _ := FilterReports(reports, FilterOptions{Namespace: "nonexistent"})

	if len(filtered) != 0 {
		t.Errorf("expected 0 reports, got %d", len(filtered))
	}
}

func TestFilterReports_NilInput(t *testing.T) {
	filtered, _ := FilterReports(nil, FilterOptions{Namespace: "default"})

	if len(filtered) != 0 {
		t.Errorf("expected 0 reports, got %d", len(filtered))
	}
}

func TestFilterReports_ByPQCStatus(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "a.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{PQCReadiness: securityv1alpha1.PQCReadinessPQCReady},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "b.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{PQCReadiness: securityv1alpha1.PQCReadinessTLS13Capable},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "c.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{PQCReadiness: securityv1alpha1.PQCReadinessLegacyTLS},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{PQCStatus: "LegacyTLS"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 LegacyTLS report, got %d", len(filtered))
	}
	if filtered[0].Spec.Host != "c.test" {
		t.Errorf("expected c.test, got %s", filtered[0].Spec.Host)
	}
}

func TestFilterReports_ByPQCStatusCaseInsensitive(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "a.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{PQCReadiness: securityv1alpha1.PQCReadinessPQCReady},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{PQCStatus: "pqcready"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
}

func TestFilterReports_ByExpired(t *testing.T) {
	now := time.Now()
	expired := metav1.NewTime(now.Add(-24 * time.Hour))
	valid := metav1.NewTime(now.Add(30 * 24 * time.Hour))

	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "expired.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{NotAfter: &expired, IsExpired: true},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "valid.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{NotAfter: &valid},
			},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "nocert.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{Expired: true})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 expired report, got %d", len(filtered))
	}
	if filtered[0].Spec.Host != "expired.test" {
		t.Errorf("expected expired.test, got %s", filtered[0].Spec.Host)
	}
}

func TestFilterReports_ByExpiresWithin(t *testing.T) {
	now := time.Now()
	expiring5d := metav1.NewTime(now.Add(5 * 24 * time.Hour))
	expiring60d := metav1.NewTime(now.Add(60 * 24 * time.Hour))
	expired := metav1.NewTime(now.Add(-24 * time.Hour))

	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "soon.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{NotAfter: &expiring5d},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "later.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{NotAfter: &expiring60d},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "dead.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{NotAfter: &expired},
			},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{ExpiresWithin: "30d"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 report expiring within 30d, got %d", len(filtered))
	}
	if filtered[0].Spec.Host != "soon.test" {
		t.Errorf("expected soon.test, got %s", filtered[0].Spec.Host)
	}
}

func TestFilterReports_CombinedWithPQC(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "a.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "prod"},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessLegacyTLS,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "b.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "prod"},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "c.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "dev"},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				PQCReadiness:     securityv1alpha1.PQCReadinessLegacyTLS,
			},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{Namespace: "prod", PQCStatus: "LegacyTLS"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
	if filtered[0].Spec.Host != "a.test" {
		t.Errorf("expected a.test, got %s", filtered[0].Spec.Host)
	}
}

func TestFilterReports_ByIssuer(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "a.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{Issuer: "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US"},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "b.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{Issuer: "CN=DigiCert Global Root G2,O=DigiCert Inc,C=US"},
			},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "c.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{Issuer: "let's encrypt"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
	if filtered[0].Spec.Host != "a.test" {
		t.Errorf("expected a.test, got %s", filtered[0].Spec.Host)
	}
}

func TestFilterReports_BySubject(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "a.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{Subject: "CN=api.example.com"},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "b.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				CertificateInfo: &securityv1alpha1.CertificateInfo{Subject: "CN=*.internal.corp"},
			},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{Subject: "example.com"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
	if filtered[0].Spec.Host != "a.test" {
		t.Errorf("expected a.test, got %s", filtered[0].Spec.Host)
	}
}

func TestFilterReports_CombinedIssuerAndStatus(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "a.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo:  &securityv1alpha1.CertificateInfo{Issuer: "CN=Self-Signed"},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "b.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
				CertificateInfo:  &securityv1alpha1.CertificateInfo{Issuer: "CN=Self-Signed"},
			},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{Issuer: "self-signed", Status: "NonCompliant"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 report, got %d", len(filtered))
	}
	if filtered[0].Spec.Host != "b.test" {
		t.Errorf("expected b.test, got %s", filtered[0].Spec.Host)
	}
}

func TestFilterReports_NoCertExcludedByIssuer(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "nocert.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{},
		},
	}

	filtered, _ := FilterReports(reports, FilterOptions{Issuer: "anything"})
	if len(filtered) != 0 {
		t.Errorf("expected 0 reports for nil cert info, got %d", len(filtered))
	}
}

func TestParseExpiresWithin(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
		err   bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"90d", 90 * 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseExpiresWithin(tt.input)
		if tt.err && err == nil {
			t.Errorf("ParseExpiresWithin(%q): expected error", tt.input)
		}
		if !tt.err && err != nil {
			t.Errorf("ParseExpiresWithin(%q): unexpected error: %v", tt.input, err)
		}
		if !tt.err && got != tt.want {
			t.Errorf("ParseExpiresWithin(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFilterReports_ByTLSVersion(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "modern.example.com", Port: 443},
			Status: securityv1alpha1.TLSComplianceReportStatus{TLSVersions: securityv1alpha1.TLSVersionSupport{TLS12: true, TLS13: true}},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "legacy.example.com", Port: 443},
			Status: securityv1alpha1.TLSComplianceReportStatus{TLSVersions: securityv1alpha1.TLSVersionSupport{TLS10: true, TLS11: true, TLS12: true}},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "ancient.example.com", Port: 443},
			Status: securityv1alpha1.TLSComplianceReportStatus{TLSVersions: securityv1alpha1.TLSVersionSupport{SSL30: true, TLS10: true}},
		},
	}

	tests := []struct {
		name      string
		version   string
		wantCount int
		wantHost  string
	}{
		{"TLS 1.3", "1.3", 1, "modern.example.com"},
		{"TLS 1.2", "1.2", 2, ""},
		{"TLS 1.0", "1.0", 2, ""},
		{"TLS 1.1", "1.1", 1, "legacy.example.com"},
		{"SSL 3.0", "ssl3.0", 1, "ancient.example.com"},
		{"case insensitive", "TLS1.3", 1, "modern.example.com"},
		{"unknown version", "2.0", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FilterReports(reports, FilterOptions{TLSVersion: tt.version})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantCount {
				t.Errorf("expected %d reports, got %d", tt.wantCount, len(got))
			}
			if tt.wantHost != "" && len(got) > 0 && got[0].Spec.Host != tt.wantHost {
				t.Errorf("expected host %q, got %q", tt.wantHost, got[0].Spec.Host)
			}
		})
	}
}
