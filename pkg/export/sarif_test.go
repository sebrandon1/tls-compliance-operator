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
	"slices"
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
	if len(log.Runs[0].Tool.Driver.Rules) != 10 {
		t.Errorf("rules = %d, want 10", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestWriteSARIF_MixedStatus(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "ok.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant, ForwardSecrecy: true, PQCReadiness: securityv1alpha1.PQCReadinessPQCReady}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "legacy.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant, ForwardSecrecy: true, PQCReadiness: securityv1alpha1.PQCReadinessTLS13Capable}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "plain.example", Port: 80}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusPlaintextHTTP}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "none.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "warn.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusWarning, ForwardSecrecy: true, PQCReadiness: securityv1alpha1.PQCReadinessTLS13Capable}},
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

// statusResult returns the compliance-status result, which reportToSARIFResults
// appends first when the status maps to a rule.
func statusResult(t *testing.T, r *securityv1alpha1.TLSComplianceReport) sarifResult {
	t.Helper()
	results := reportToSARIFResults(r)
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	return results[0]
}

func TestSARIFResult_FingerprintIsStable(t *testing.T) {
	r := sarifReportForTest("prod")

	first := statusResult(t, r).PartialFingerprints[sarifFingerprintKey]
	second := statusResult(t, r).PartialFingerprints[sarifFingerprintKey]

	if first == "" {
		t.Fatal("expected a partialFingerprints entry")
	}
	if len(first) != 64 {
		t.Errorf("fingerprint = %q, want 64 hex characters", first)
	}
	if second != first {
		t.Errorf("fingerprint not stable across calls: %q != %q", first, second)
	}
}

func TestSARIFResult_FingerprintTracksSource(t *testing.T) {
	prod := statusResult(t, sarifReportForTest("prod")).PartialFingerprints[sarifFingerprintKey]
	staging := statusResult(t, sarifReportForTest("staging")).PartialFingerprints[sarifFingerprintKey]
	if prod == staging {
		t.Errorf("expected differing fingerprints for different namespaces, got %q for both", prod)
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

func TestSARIFRules_AllHaveHelpURI(t *testing.T) {
	for _, rule := range sarifRules {
		if rule.HelpURI == "" {
			t.Errorf("rule %q has no helpUri", rule.ID)
		}
	}
}

func TestSARIFResultMessage_NamesSourceObject(t *testing.T) {
	want := "Route prod/api-443 (api.example:443) is NonCompliant"
	if got := statusResult(t, sarifReportForTest("prod")).Message.Text; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
}

func TestSARIFResultMessage_FallsBackWithoutSource(t *testing.T) {
	r := &securityv1alpha1.TLSComplianceReport{
		Spec:   securityv1alpha1.TLSComplianceReportSpec{Host: "bare.example", Port: 443},
		Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusWarning},
	}
	want := "bare.example:443 is Warning"
	if got := statusResult(t, r).Message.Text; got != want {
		t.Errorf("message = %q, want %q", got, want)
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

func sarifTLSReport(status securityv1alpha1.ComplianceStatus) *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "tls.example", Port: 443},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: status,
			ForwardSecrecy:   true,
			PQCReadiness:     securityv1alpha1.PQCReadinessPQCReady,
		},
	}
}

func sarifRuleIDs(results []sarifResult) []string {
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.RuleID)
	}
	return ids
}

func TestReportToSARIFResults_CertificateFindings(t *testing.T) {
	cases := []struct {
		name string
		cert *securityv1alpha1.CertificateInfo
		want []string
	}{
		{
			name: "no certificate record",
			cert: nil,
			want: nil,
		},
		{
			name: "healthy certificate",
			cert: &securityv1alpha1.CertificateInfo{DaysUntilExpiry: 200},
			want: nil,
		},
		{
			name: "expired certificate",
			cert: &securityv1alpha1.CertificateInfo{IsExpired: true, DaysUntilExpiry: -3},
			want: []string{sarifRuleCertificateExpired},
		},
		{
			name: "expiring soon",
			cert: &securityv1alpha1.CertificateInfo{DaysUntilExpiry: sarifCertExpiryWarningDays},
			want: []string{sarifRuleCertificateExpiring},
		},
		{
			name: "just outside the horizon",
			cert: &securityv1alpha1.CertificateInfo{DaysUntilExpiry: sarifCertExpiryWarningDays + 1},
			want: nil,
		},
		{
			name: "untrusted chain",
			cert: &securityv1alpha1.CertificateInfo{
				DaysUntilExpiry: 200, Trusted: boolPtr(false), TrustError: "x509: certificate signed by unknown authority",
			},
			want: []string{sarifRuleCertificateUntrusted},
		},
		{
			name: "trusted chain",
			cert: &securityv1alpha1.CertificateInfo{DaysUntilExpiry: 200, Trusted: boolPtr(true)},
			want: nil,
		},
		{
			name: "unknown trust is not a finding",
			cert: &securityv1alpha1.CertificateInfo{DaysUntilExpiry: 200},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := sarifTLSReport(securityv1alpha1.ComplianceStatusCompliant)
			r.Status.CertificateInfo = tc.cert
			if got := sarifRuleIDs(reportToSARIFResults(r)); !slices.Equal(got, tc.want) {
				t.Errorf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReportToSARIFResults_CipherAndPQC(t *testing.T) {
	cases := []struct {
		name  string
		mutfn func(*securityv1alpha1.TLSComplianceReport)
		want  []string
	}{
		{
			name:  "weak grade",
			mutfn: func(r *securityv1alpha1.TLSComplianceReport) { r.Status.OverallCipherGrade = "F" },
			want:  []string{sarifRuleWeakCipher},
		},
		{
			name:  "grade C is fine",
			mutfn: func(r *securityv1alpha1.TLSComplianceReport) { r.Status.OverallCipherGrade = "C" },
			want:  nil,
		},
		{
			name:  "no forward secrecy",
			mutfn: func(r *securityv1alpha1.TLSComplianceReport) { r.Status.ForwardSecrecy = false },
			want:  []string{sarifRuleNoForwardSecrecy},
		},
		{
			name: "legacy PQC",
			mutfn: func(r *securityv1alpha1.TLSComplianceReport) {
				r.Status.PQCReadiness = securityv1alpha1.PQCReadinessLegacyTLS
			},
			want: []string{sarifRulePQCNotReady},
		},
		{
			name: "no PQC",
			mutfn: func(r *securityv1alpha1.TLSComplianceReport) {
				r.Status.PQCReadiness = securityv1alpha1.PQCReadinessNoPQC
			},
			want: []string{sarifRulePQCNotReady},
		},
		{
			name: "TLS 1.3 capable is not a finding",
			mutfn: func(r *securityv1alpha1.TLSComplianceReport) {
				r.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := sarifTLSReport(securityv1alpha1.ComplianceStatusCompliant)
			tc.mutfn(r)
			if got := sarifRuleIDs(reportToSARIFResults(r)); !slices.Equal(got, tc.want) {
				t.Errorf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReportToSARIFResults_ConnectivityStatusHasNoFindings(t *testing.T) {
	for _, status := range []securityv1alpha1.ComplianceStatus{
		securityv1alpha1.ComplianceStatusTimeout,
		securityv1alpha1.ComplianceStatusClosed,
		securityv1alpha1.ComplianceStatusUnreachable,
		securityv1alpha1.ComplianceStatusNoTLS,
		securityv1alpha1.ComplianceStatusPlaintextHTTP,
		securityv1alpha1.ComplianceStatusMutualTLSRequired,
	} {
		t.Run(string(status), func(t *testing.T) {
			r := sarifTLSReport(status)
			r.Status.CertificateInfo = &securityv1alpha1.CertificateInfo{IsExpired: true}
			r.Status.ForwardSecrecy = false
			r.Status.PQCReadiness = securityv1alpha1.PQCReadinessNoPQC
			r.Status.OverallCipherGrade = "F"
			for _, result := range reportToSARIFResults(r) {
				switch result.RuleID {
				case sarifRuleCertificateExpired, sarifRuleCertificateExpiring,
					sarifRuleWeakCipher, sarifRuleNoForwardSecrecy, sarifRulePQCNotReady:
					t.Errorf("unexpected %s result for %s", result.RuleID, status)
				}
			}
		})
	}
}

func TestWriteSARIF_Deterministic(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "b.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusWarning}},
		{Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "a.example", Port: 443}, Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant}},
	}
	var first, second bytes.Buffer
	if err := WriteSARIF(&first, reports); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIF(&second, reports); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Error("expected byte-identical output across two exports")
	}

	results := decodeSARIF(t, &first).Runs[0].Results
	for i := 1; i < len(results); i++ {
		if results[i-1].RuleID > results[i].RuleID {
			t.Errorf("results are not sorted by rule id: %q before %q", results[i-1].RuleID, results[i].RuleID)
		}
	}
}
