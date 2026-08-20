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

func TestWriteHTML_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<html") {
		t.Fatal("expected HTML document")
	}
	if !strings.Contains(out, "0 endpoints") {
		t.Errorf("expected 0 endpoints, got: %s", out)
	}
	if strings.Contains(out, "<tbody>\n<tr>") {
		t.Error("expected no data rows for empty input")
	}
}

func TestWriteHTML_MixedStatus(t *testing.T) {
	now := time.Now()
	created := metav1.NewTime(now.Add(-5 * time.Minute))
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			ObjectMeta: metav1.ObjectMeta{CreationTimestamp: created},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "ok.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusCompliant,
				OverallCipherGrade: "A",
				ForwardSecrecy:     true,
				TLSVersions:        securityv1alpha1.TLSVersionSupport{TLS13: true, TLS12: true},
				PQCReadiness:       securityv1alpha1.PQCReadinessPQCReady,
				CertificateInfo:    &securityv1alpha1.CertificateInfo{DaysUntilExpiry: 364},
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "bad.example",
				Port:       80,
				SourceKind: securityv1alpha1.SourceKindIngress,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusNonCompliant,
				OverallCipherGrade: "F",
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "warn.example",
				Port:       8443,
				SourceKind: securityv1alpha1.SourceKindRoute,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusWarning,
				OverallCipherGrade: "C",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"ok.example", "bad.example", "warn.example",
		"364", "5m",
		`class="pill ok">Compliant`,
		`class="pill bad">NonCompliant`,
		`class="pill warn">Warning`,
		`class="pill ok">A`,
		`class="pill bad">F`,
		`class="pill warn">C`,
		"3 endpoints",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestWriteHTML_EscapesHost(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{Host: `<script>alert("x")</script>`},
		},
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, reports); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") {
		t.Fatal("host was not HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped host, got: %s", out)
	}
}

func TestComplianceHTMLClass(t *testing.T) {
	tests := []struct {
		status securityv1alpha1.ComplianceStatus
		want   string
	}{
		{securityv1alpha1.ComplianceStatusCompliant, "ok"},
		{securityv1alpha1.ComplianceStatusWarning, "warn"},
		{securityv1alpha1.ComplianceStatusMutualTLSRequired, "warn"},
		{securityv1alpha1.ComplianceStatusNonCompliant, "bad"},
		{securityv1alpha1.ComplianceStatusNoTLS, "bad"},
		{securityv1alpha1.ComplianceStatusPlaintextHTTP, "bad"},
		{securityv1alpha1.ComplianceStatusTimeout, "info"},
	}
	for _, tt := range tests {
		if got := complianceHTMLClass(tt.status); got != tt.want {
			t.Errorf("complianceHTMLClass(%s) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestGradeHTMLClass(t *testing.T) {
	tests := map[string]string{"A": "ok", "B": "ok", "C": "warn", "D": "bad", "F": "bad", "": "info"}
	for grade, want := range tests {
		if got := gradeHTMLClass(grade); got != want {
			t.Errorf("gradeHTMLClass(%q) = %q, want %q", grade, got, want)
		}
	}
}
