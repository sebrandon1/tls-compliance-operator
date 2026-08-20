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
	"strings"
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func decodeSARIF(t *testing.T, buf *bytes.Buffer) sarifLog {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	return log
}

func TestWriteSARIF_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil); err != nil {
		t.Fatal(err)
	}
	log := decodeSARIF(t, &buf)
	if log.Version != "2.1.0" {
		t.Errorf("version = %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "tls-compliance-operator" {
		t.Errorf("driver name = %q", log.Runs[0].Tool.Driver.Name)
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 4 {
		t.Errorf("rules = %d, want 4", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestWriteSARIF_MixedStatus(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "ok.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "legacy.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "plain.example", Port: 80}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusPlaintextHTTP}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "none.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "warn.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusWarning}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "timeout.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusTimeout}},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, reports); err != nil {
		t.Fatal(err)
	}
	log := decodeSARIF(t, &buf)
	results := log.Runs[0].Results
	if len(results) != 4 {
		t.Fatalf("results = %d, want 4 (skip Compliant and Timeout)", len(results))
	}

	got := map[string]sarifResult{}
	for _, r := range results {
		got[r.RuleID] = r
	}
	if got[sarifRuleNonCompliant].Level != "error" || !strings.Contains(got[sarifRuleNonCompliant].Locations[0].PhysicalLocation.ArtifactLocation.URI, "legacy.example:443") {
		t.Errorf("non-compliant result = %+v", got[sarifRuleNonCompliant])
	}
	if got[sarifRulePlaintextHTTP].Level != "error" {
		t.Errorf("plaintext level = %q", got[sarifRulePlaintextHTTP].Level)
	}
	if got[sarifRuleNoTLS].Level != "error" {
		t.Errorf("no-tls level = %q", got[sarifRuleNoTLS].Level)
	}
	if got[sarifRuleWarning].Level != "warning" {
		t.Errorf("warning level = %q", got[sarifRuleWarning].Level)
	}
}

func TestWriteSARIF_IPv6(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "2001:db8::1", Port: 443},
			Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant},
		},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, reports); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "tls://[2001:db8::1]:443") {
		t.Errorf("expected IPv6 JoinHostPort URI, got: %s", out)
	}
}
