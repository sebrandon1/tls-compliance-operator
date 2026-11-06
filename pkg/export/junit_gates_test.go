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
	"encoding/xml"
	"strings"
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// gateReport builds a report carrying the fields the CI gates read.
func gateReport(
	host string, status securityv1alpha1.ComplianceStatus,
	readiness securityv1alpha1.PQCReadiness, curves map[string]string,
) securityv1alpha1.TLSComplianceReport {
	return securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            host,
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: "prod",
			SourceName:      host,
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: status,
			PQCReadiness:     readiness,
			NegotiatedCurves: curves,
		},
	}
}

// writeCases renders reports with opts and returns the parsed suite.
func writeCases(t *testing.T, reports []securityv1alpha1.TLSComplianceReport, opts JUnitOptions) JUnitTestSuite {
	t.Helper()

	var buf bytes.Buffer
	if err := WriteJUnitWithOptions(&buf, reports, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if len(suites.TestSuites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.TestSuites))
	}
	return suites.TestSuites[0]
}

func TestWriteJUnitWithOptions_PQCGateFailsEndpoint(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("legacy-acme.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessTLS13Capable, nil),
	}

	suite := writeCases(t, reports, JUnitOptions{RequirePQC: true})

	if suite.Failures != 1 {
		t.Fatalf("Failures = %d, want 1", suite.Failures)
	}
	failure := suite.TestCases[0].Failure
	if failure == nil {
		t.Fatal("expected a failure on a TLS13Capable endpoint")
	}
	if want := "PQC gate: TLS13Capable (want PQCReady)"; failure.Message != want {
		t.Errorf("Message = %q, want %q", failure.Message, want)
	}
	if !strings.Contains(failure.Text, "legacy-acme.example:443 is TLS13Capable") {
		t.Errorf("Text = %q, want it to name the endpoint and readiness", failure.Text)
	}
}

func TestWriteJUnitWithOptions_PQCGatePassesReadyEndpoint(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("pqc.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessPQCReady, nil),
	}

	suite := writeCases(t, reports, JUnitOptions{RequirePQC: true})

	if suite.Failures != 0 || suite.TestCases[0].Failure != nil {
		t.Errorf("PQC-ready endpoint must pass, got %+v", suite.TestCases[0].Failure)
	}
}

func TestWriteJUnitWithOptions_PQCGateSkipsUnassertedEndpoints(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("no-tls.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessNoPQC, nil),
		gateReport("unreachable.example", securityv1alpha1.ComplianceStatusTimeout,
			securityv1alpha1.PQCReadinessLegacyTLS, nil),
	}

	suite := writeCases(t, reports, JUnitOptions{RequirePQC: true})

	// NoPQC is skipped by the gate, so the case keeps passing.
	if suite.TestCases[0].Failure != nil {
		t.Errorf("NoPQC endpoint must be skipped, got %+v", suite.TestCases[0].Failure)
	}
	// An unscannable endpoint was already failing for its own reason; the gate
	// must not relabel it.
	if got := suite.TestCases[1].Failure.Message; !strings.HasPrefix(got, "Timeout:") {
		t.Errorf("Timeout case Message = %q, want the compliance failure", got)
	}
}

func TestWriteJUnitWithOptions_GroupGateReportsMissing(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("classic.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessPQCReady, map[string]string{"TLS 1.3": "X25519"}),
	}

	suite := writeCases(t, reports, JUnitOptions{
		ExpectedGroups: []string{"X25519MLKEM768"},
		GroupsMode:     GroupsModeContains,
	})

	failure := suite.TestCases[0].Failure
	if failure == nil {
		t.Fatal("expected a failure for a missing group")
	}
	if want := "Expected groups: missing X25519MLKEM768"; failure.Message != want {
		t.Errorf("Message = %q, want %q", failure.Message, want)
	}
	if !strings.Contains(failure.Text, "advertised: X25519") {
		t.Errorf("Text = %q, want the advertised groups", failure.Text)
	}
}

func TestWriteJUnitWithOptions_GroupGateReportsUnexpectedInExactMode(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("extra.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessPQCReady, map[string]string{"TLS 1.3": "X25519MLKEM768"}),
	}

	suite := writeCases(t, reports, JUnitOptions{
		ExpectedGroups: []string{"X25519"},
		GroupsMode:     GroupsModeExact,
	})

	failure := suite.TestCases[0].Failure
	if failure == nil {
		t.Fatal("expected a failure for an unexpected group")
	}
	if want := "Expected groups: missing X25519; unexpected X25519MLKEM768"; failure.Message != want {
		t.Errorf("Message = %q, want %q", failure.Message, want)
	}
}

func TestWriteJUnitWithOptions_GroupGateSkipsUnenumerableEndpoint(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("no-curves.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessPQCReady, nil),
	}

	suite := writeCases(t, reports, JUnitOptions{
		ExpectedGroups: []string{"X25519"},
		GroupsMode:     GroupsModeContains,
	})

	if suite.TestCases[0].Failure != nil {
		t.Errorf("endpoint without groups must be skipped, got %+v", suite.TestCases[0].Failure)
	}
}

func TestWriteJUnitWithOptions_CombinesBothGates(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("both.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessTLS13Capable, map[string]string{"TLS 1.3": "X25519"}),
	}

	suite := writeCases(t, reports, JUnitOptions{
		RequirePQC:     true,
		ExpectedGroups: []string{"X25519MLKEM768"},
		GroupsMode:     GroupsModeContains,
	})

	failure := suite.TestCases[0].Failure
	if failure == nil {
		t.Fatal("expected a failure")
	}
	want := "PQC gate: TLS13Capable (want PQCReady); Expected groups: missing X25519MLKEM768"
	if failure.Message != want {
		t.Errorf("Message = %q, want %q", failure.Message, want)
	}
}

func TestWriteJUnitWithOptions_ComplianceFailureWins(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("broken.example", securityv1alpha1.ComplianceStatusNonCompliant,
			securityv1alpha1.PQCReadinessLegacyTLS, map[string]string{"TLS 1.2": "X25519"}),
	}

	suite := writeCases(t, reports, JUnitOptions{
		RequirePQC:     true,
		ExpectedGroups: []string{"X25519MLKEM768"},
		GroupsMode:     GroupsModeContains,
	})

	failure := suite.TestCases[0].Failure
	if failure == nil {
		t.Fatal("expected a failure")
	}
	if !strings.HasPrefix(failure.Message, "NonCompliant:") {
		t.Errorf("Message = %q, want the compliance failure to be reported", failure.Message)
	}
}

func TestWriteJUnit_NoOptionsKeepsCompliantEndpointPassing(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		gateReport("plain.example", securityv1alpha1.ComplianceStatusCompliant,
			securityv1alpha1.PQCReadinessLegacyTLS, map[string]string{"TLS 1.2": "X25519"}),
	}

	suite := writeCases(t, reports, JUnitOptions{})

	if suite.Failures != 0 {
		t.Errorf("Failures = %d without gates, want 0", suite.Failures)
	}
}
