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
	"fmt"
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

func TestWriteCSV_AllComplianceStatuses(t *testing.T) {
	statuses := []securityv1alpha1.ComplianceStatus{
		securityv1alpha1.ComplianceStatusCompliant,
		securityv1alpha1.ComplianceStatusNonCompliant,
		securityv1alpha1.ComplianceStatusWarning,
		securityv1alpha1.ComplianceStatusUnreachable,
		securityv1alpha1.ComplianceStatusTimeout,
		securityv1alpha1.ComplianceStatusClosed,
		securityv1alpha1.ComplianceStatusFiltered,
		securityv1alpha1.ComplianceStatusNoTLS,
		securityv1alpha1.ComplianceStatusMutualTLSRequired,
		securityv1alpha1.ComplianceStatusPending,
		securityv1alpha1.ComplianceStatusUnknown,
	}

	var reports []securityv1alpha1.TLSComplianceReport
	for i, s := range statuses {
		reports = append(reports, securityv1alpha1.TLSComplianceReport{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            fmt.Sprintf("svc%d.test", i),
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "test",
				SourceName:      fmt.Sprintf("svc%d", i),
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: s,
			},
		})
	}

	var buf bytes.Buffer
	err := WriteCSV(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	for _, s := range statuses {
		if !strings.Contains(output, string(s)) {
			t.Errorf("expected CSV to contain status %q", s)
		}
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != len(statuses)+1 {
		t.Fatalf("expected %d lines, got %d", len(statuses)+1, len(lines))
	}
}

func TestWriteCSV_AllSourceKinds(t *testing.T) {
	kinds := []securityv1alpha1.SourceKind{
		securityv1alpha1.SourceKindService,
		securityv1alpha1.SourceKindIngress,
		securityv1alpha1.SourceKindRoute,
		securityv1alpha1.SourceKindTarget,
		securityv1alpha1.SourceKindPod,
	}

	var reports []securityv1alpha1.TLSComplianceReport
	for i, k := range kinds {
		reports = append(reports, securityv1alpha1.TLSComplianceReport{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            fmt.Sprintf("ep%d.test", i),
				Port:            443,
				SourceKind:      k,
				SourceNamespace: "test",
				SourceName:      fmt.Sprintf("ep%d", i),
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		})
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	for _, k := range kinds {
		if !strings.Contains(output, string(k)) {
			t.Errorf("expected CSV to contain source kind %q", k)
		}
	}
}

func TestWriteCSV_KeyExchangeTypes(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "multi-ke.test",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "test",
				SourceName:      "multi-ke",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				KeyExchangeTypes: map[string]string{
					"TLS 1.2": "ECDHE",
					"TLS 1.3": "TLS13",
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ECDHE") {
		t.Error("expected CSV to contain ECDHE")
	}
	if !strings.Contains(output, "TLS13") {
		t.Error("expected CSV to contain TLS13")
	}
}

func TestWriteCSV_SpecialCharacters(t *testing.T) {
	expiry := metav1.NewTime(time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "svc-with-special.ns-with-dash",
				Port:            8443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "ns-with-dash",
				SourceName:      "svc-with-special",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CertificateInfo: &securityv1alpha1.CertificateInfo{
					Issuer:   "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
					NotAfter: &expiry,
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Let's Encrypt") {
		t.Error("expected CSV to handle apostrophe in issuer")
	}
	if !strings.Contains(output, "ns-with-dash") {
		t.Error("expected CSV to handle dashes in namespace")
	}
}

func TestWriteCSV_AllTLSVersionCombinations(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "all-versions.test",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "test",
				SourceName:      "all-versions",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
				TLSVersions: securityv1alpha1.TLSVersionSupport{
					SSL30: true,
					TLS10: true,
					TLS11: true,
					TLS12: true,
					TLS13: true,
				},
				ForwardSecrecy: true,
				QuantumReady:   true,
				PQCReadiness:   securityv1alpha1.PQCReadinessPQCReady,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	row := lines[1]
	for _, field := range []string{"true", "NonCompliant", "PQCReady"} {
		if !strings.Contains(row, field) {
			t.Errorf("expected row to contain %q", field)
		}
	}
}
