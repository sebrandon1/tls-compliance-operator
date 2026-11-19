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

func sarifReportForTest(namespace string) *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "api.example",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindRoute,
			SourceNamespace: namespace,
			SourceName:      "api-443",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant},
	}
}

func TestSARIFResult_FingerprintIsStable(t *testing.T) {
	r := sarifReportForTest("prod")

	first, ok := reportToSARIFResult(r)
	if !ok {
		t.Fatal("expected a result")
	}
	second, ok := reportToSARIFResult(r)
	if !ok {
		t.Fatal("expected a result")
	}

	fp := first.PartialFingerprints[sarifFingerprintKey]
	if fp == "" {
		t.Fatal("expected a partialFingerprints entry")
	}
	if len(fp) != 64 {
		t.Errorf("fingerprint = %q, want 64 hex characters", fp)
	}
	if second.PartialFingerprints[sarifFingerprintKey] != fp {
		t.Errorf("fingerprint not stable across calls: %q != %q", fp, second.PartialFingerprints[sarifFingerprintKey])
	}
}

func TestSARIFResult_FingerprintTracksSource(t *testing.T) {
	prod, _ := reportToSARIFResult(sarifReportForTest("prod"))
	staging, _ := reportToSARIFResult(sarifReportForTest("staging"))

	prodFP := prod.PartialFingerprints[sarifFingerprintKey]
	stagingFP := staging.PartialFingerprints[sarifFingerprintKey]
	if prodFP == stagingFP {
		t.Errorf("expected differing fingerprints for different namespaces, got %q for both", prodFP)
	}
}

func TestSARIFRules_AllHaveHelpURI(t *testing.T) {
	for _, rule := range sarifRules {
		if rule.HelpURI == "" {
			t.Errorf("rule %q has no helpUri", rule.ID)
		}
	}
}

func TestSARIFResultMessage_NamesSourceObject(t *testing.T) {
	result, ok := reportToSARIFResult(sarifReportForTest("prod"))
	if !ok {
		t.Fatal("expected a result")
	}
	want := "Route prod/api-443 (api.example:443) is NonCompliant"
	if result.Message.Text != want {
		t.Errorf("message = %q, want %q", result.Message.Text, want)
	}
}

func TestSARIFResultMessage_FallsBackWithoutSource(t *testing.T) {
	r := &securityv1alpha1.TLSComplianceReport{
		Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "bare.example", Port: 443},
		Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusWarning},
	}
	result, ok := reportToSARIFResult(r)
	if !ok {
		t.Fatal("expected a result")
	}
	want := "bare.example:443 is Warning"
	if result.Message.Text != want {
		t.Errorf("message = %q, want %q", result.Message.Text, want)
	}
}

func TestSARIFSourceObject(t *testing.T) {
	cases := []struct {
		name string
		spec securityv1alpha1.TLSComplianceReportSpec
		want string
	}{
		{
			name: "kind namespace and name",
			spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindRoute, SourceNamespace: "prod", SourceName: "api-443"},
			want: "Route prod/api-443",
		},
		{
			name: "no namespace",
			spec: securityv1alpha1.TLSComplianceReportSpec{SourceKind: securityv1alpha1.SourceKindTarget, SourceName: "target"},
			want: "Target target",
		},
		{
			name: "no kind",
			spec: securityv1alpha1.TLSComplianceReportSpec{SourceNamespace: "prod", SourceName: "api-443"},
			want: "prod/api-443",
		},
		{
			name: "no source at all",
			spec: securityv1alpha1.TLSComplianceReportSpec{Host: "bare.example"},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &securityv1alpha1.TLSComplianceReport{Spec: tc.spec}
			if got := sarifSourceObject(r); got != tc.want {
				t.Errorf("sarifSourceObject() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSARIFFingerprint_IncludesRuleAndEndpoint(t *testing.T) {
	r := sarifReportForTest("prod")
	base := sarifFingerprint(sarifRuleWarning, r)

	if got := sarifFingerprint(sarifRuleNoTLS, r); got == base {
		t.Error("expected different rule ids to produce different fingerprints")
	}

	other := sarifReportForTest("prod")
	other.Spec.Port = 8443
	if got := sarifFingerprint(sarifRuleWarning, other); got == base {
		t.Error("expected different ports to produce different fingerprints")
	}
}
