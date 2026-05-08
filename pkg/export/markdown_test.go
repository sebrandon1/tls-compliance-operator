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

func TestWriteMarkdown_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteMarkdown(&buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + separator), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "| Host") {
		t.Errorf("expected header to start with '| Host', got: %s", lines[0])
	}
	if !strings.Contains(lines[1], "---") {
		t.Errorf("expected separator row with ---, got: %s", lines[1])
	}
}

func TestWriteMarkdown_SingleReport(t *testing.T) {
	now := time.Now()
	created := metav1.NewTime(now.Add(-5 * time.Minute))

	reports := []securityv1alpha1.TLSComplianceReport{
		{
			ObjectMeta: metav1.ObjectMeta{CreationTimestamp: created},
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
				ForwardSecrecy:     true,
				TLSVersions: securityv1alpha1.TLSVersionSupport{
					TLS13: true,
					TLS12: true,
				},
				PQCReadiness: securityv1alpha1.PQCReadinessPQCReady,
				CertificateInfo: &securityv1alpha1.CertificateInfo{
					DaysUntilExpiry: 364,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteMarkdown(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + separator + 1 row), got %d", len(lines))
	}

	row := lines[2]
	for _, field := range []string{"my-service.default", "443", "Service", "Compliant", "A", "PQCReady", "364", "5m"} {
		if !strings.Contains(row, field) {
			t.Errorf("expected row to contain %q, got: %s", field, row)
		}
	}
}

func TestWriteMarkdown_MultipleReports(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "svc1.ns1", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant},
		},
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "svc2.ns2", Port: 8443, SourceKind: securityv1alpha1.SourceKindRoute},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant},
		},
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines (header + separator + 2 rows), got %d", len(lines))
	}
}

func TestWriteMarkdown_NoCertificate(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "no-cert.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS},
		},
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	row := lines[2]
	if !strings.Contains(row, "NoTLS") {
		t.Error("expected row to contain NoTLS")
	}
}

func TestWriteMarkdown_TableStructure(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "test.example", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant},
		},
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			t.Errorf("line %d should start and end with pipe: %s", i, line)
		}
	}

	headerPipes := strings.Count(lines[0], "|")
	for i, line := range lines[1:] {
		if strings.Count(line, "|") != headerPipes {
			t.Errorf("line %d has %d pipes, expected %d (same as header)", i+1, strings.Count(line, "|"), headerPipes)
		}
	}
}

func TestWriteMarkdown_AllComplianceStatuses(t *testing.T) {
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
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: fmt.Sprintf("svc%d.test", i), Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: s},
		})
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	for _, s := range statuses {
		if !strings.Contains(output, string(s)) {
			t.Errorf("expected output to contain status %q", s)
		}
	}
}

func TestWriteMarkdown_PipeEscaping(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "host|with|pipes.test", Port: 443, SourceKind: securityv1alpha1.SourceKindService},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant},
		},
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	row := lines[2]
	if !strings.Contains(row, `host\|with\|pipes.test`) {
		t.Errorf("expected pipes in host to be escaped, got: %s", row)
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{2 * time.Hour, "2h"},
		{3 * 24 * time.Hour, "3d"},
		{90 * 24 * time.Hour, "90d"},
	}

	for _, tt := range tests {
		got := formatAge(tt.d)
		if got != tt.want {
			t.Errorf("formatAge(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
