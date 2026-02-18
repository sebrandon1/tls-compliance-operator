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

func TestWriteCSV_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCSV(&buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line (header only), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "Host,") {
		t.Errorf("expected header to start with Host, got: %s", lines[0])
	}
}

func TestWriteCSV_SingleReport(t *testing.T) {
	expiry := metav1.NewTime(time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "my-service.default",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "default",
				SourceName:      "my-service",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusCompliant,
				OverallCipherGrade: "A",
				TLSVersions: securityv1alpha1.TLSVersionSupport{
					TLS13: true,
					TLS12: true,
				},
				CertificateInfo: &securityv1alpha1.CertificateInfo{
					NotAfter: &expiry,
					Issuer:   "Let's Encrypt",
				},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteCSV(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	data := lines[1]
	expected := []string{
		"my-service.default", "443", "Service", "default", "my-service",
		"Compliant", "A",
		"true", "true", "false", "false",
		"false",
		"2026-06-15", "Let's Encrypt",
	}
	for _, field := range expected {
		if !strings.Contains(data, field) {
			t.Errorf("expected CSV row to contain %q, got: %s", field, data)
		}
	}
}

func TestWriteCSV_NoCertificate(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "no-cert.example",
				Port:            8080,
				SourceKind:      securityv1alpha1.SourceKindIngress,
				SourceNamespace: "test",
				SourceName:      "no-cert",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS,
			},
		},
	}

	var buf bytes.Buffer
	err := WriteCSV(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	if !strings.Contains(lines[1], "NoTLS") {
		t.Errorf("expected CSV to contain NoTLS status")
	}
}

func TestWriteCSV_MultipleReports(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "svc1.ns1",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "ns1",
				SourceName:      "svc1",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "svc2.ns2",
				Port:            8443,
				SourceKind:      securityv1alpha1.SourceKindRoute,
				SourceNamespace: "ns2",
				SourceName:      "svc2",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			},
		},
	}

	var buf bytes.Buffer
	err := WriteCSV(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 rows), got %d", len(lines))
	}
}
