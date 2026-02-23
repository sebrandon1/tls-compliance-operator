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
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result []JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty array, got %d items", len(result))
	}
}

func TestWriteJSON_SingleReport(t *testing.T) {
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
				QuantumReady: true,
				CertificateInfo: &securityv1alpha1.CertificateInfo{
					NotAfter: &expiry,
					Issuer:   "Let's Encrypt",
				},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result []JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 item, got %d", len(result))
	}

	r := result[0]
	if r.Host != "my-service.default" {
		t.Errorf("expected host my-service.default, got %s", r.Host)
	}
	if r.Port != "443" {
		t.Errorf("expected port 443, got %s", r.Port)
	}
	if r.Source != "Service" {
		t.Errorf("expected source Service, got %s", r.Source)
	}
	if r.Namespace != "default" {
		t.Errorf("expected namespace default, got %s", r.Namespace)
	}
	if r.Name != "my-service" {
		t.Errorf("expected name my-service, got %s", r.Name)
	}
	if r.Compliance != "Compliant" {
		t.Errorf("expected compliance Compliant, got %s", r.Compliance)
	}
	if r.Grade != "A" {
		t.Errorf("expected grade A, got %s", r.Grade)
	}
	if !r.TLS13 {
		t.Error("expected TLS13 true")
	}
	if !r.TLS12 {
		t.Error("expected TLS12 true")
	}
	if r.TLS11 {
		t.Error("expected TLS11 false")
	}
	if r.TLS10 {
		t.Error("expected TLS10 false")
	}
	if !r.QuantumReady {
		t.Error("expected QuantumReady true")
	}
	if r.CertExpiry != "2026-06-15" {
		t.Errorf("expected certExpiry 2026-06-15, got %s", r.CertExpiry)
	}
	if r.CertIssuer != "Let's Encrypt" {
		t.Errorf("expected certIssuer Let's Encrypt, got %s", r.CertIssuer)
	}
}

func TestWriteJSON_NoCertificate(t *testing.T) {
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
	err := WriteJSON(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result []JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result[0].CertExpiry != "" {
		t.Errorf("expected empty certExpiry, got %s", result[0].CertExpiry)
	}
	if result[0].CertIssuer != "" {
		t.Errorf("expected empty certIssuer, got %s", result[0].CertIssuer)
	}
}

func TestWriteJSON_MultipleReports(t *testing.T) {
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
	err := WriteJSON(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result []JSONReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result))
	}
	if result[0].Source != "Service" {
		t.Errorf("expected first source Service, got %s", result[0].Source)
	}
	if result[1].Source != "Route" {
		t.Errorf("expected second source Route, got %s", result[1].Source)
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	expiry := metav1.NewTime(time.Date(2026, 12, 25, 0, 0, 0, 0, time.UTC))
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "roundtrip.example",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "prod",
				SourceName:      "roundtrip-svc",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusCompliant,
				OverallCipherGrade: "B",
				TLSVersions: securityv1alpha1.TLSVersionSupport{
					TLS13: true,
					TLS12: true,
					TLS11: false,
					TLS10: false,
				},
				CertificateInfo: &securityv1alpha1.CertificateInfo{
					NotAfter: &expiry,
					Issuer:   "DigiCert",
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Round-trip: unmarshal and re-marshal, compare
	var parsed []JSONReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	remarshaled, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		t.Fatalf("remarshal failed: %v", err)
	}

	// Re-parse the remarshaled JSON
	var reparsed []JSONReport
	if err := json.Unmarshal(remarshaled, &reparsed); err != nil {
		t.Fatalf("re-unmarshal failed: %v", err)
	}

	if len(reparsed) != 1 {
		t.Fatalf("expected 1 item after round-trip, got %d", len(reparsed))
	}
	if reparsed[0].Host != "roundtrip.example" {
		t.Errorf("host mismatch after round-trip: %s", reparsed[0].Host)
	}
	if reparsed[0].Grade != "B" {
		t.Errorf("grade mismatch after round-trip: %s", reparsed[0].Grade)
	}
}
