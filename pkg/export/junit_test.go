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

func TestWriteJUnit_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJUnit(&buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if len(suites.TestSuites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.TestSuites))
	}
	if suites.TestSuites[0].Tests != 0 {
		t.Errorf("expected 0 tests, got %d", suites.TestSuites[0].Tests)
	}
}

func TestWriteJUnit_CompliantPass(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "secure.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				TLSVersions: securityv1alpha1.TLSVersionSupport{
					TLS13: true,
					TLS12: true,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJUnit(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	suite := suites.TestSuites[0]
	if suite.Tests != 1 {
		t.Errorf("expected 1 test, got %d", suite.Tests)
	}
	if suite.Failures != 0 {
		t.Errorf("expected 0 failures, got %d", suite.Failures)
	}
	if suite.TestCases[0].Failure != nil {
		t.Error("expected no failure for compliant endpoint")
	}
	if suite.TestCases[0].Name != "secure.example:443" {
		t.Errorf("unexpected test name: %s", suite.TestCases[0].Name)
	}
	if suite.TestCases[0].ClassName != "Service" {
		t.Errorf("unexpected classname: %s", suite.TestCases[0].ClassName)
	}
}

func TestWriteJUnit_NonCompliantFail(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "legacy.example",
				Port:       8443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
				TLSVersions: securityv1alpha1.TLSVersionSupport{
					TLS10: true,
					TLS11: true,
				},
				OverallCipherGrade: "D",
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJUnit(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	suite := suites.TestSuites[0]
	if suite.Failures != 1 {
		t.Errorf("expected 1 failure, got %d", suite.Failures)
	}
	tc := suite.TestCases[0]
	if tc.Failure == nil {
		t.Fatal("expected failure for non-compliant endpoint")
	}
	if !strings.Contains(tc.Failure.Message, "NonCompliant") {
		t.Errorf("expected NonCompliant in failure message, got: %s", tc.Failure.Message)
	}
	if !strings.Contains(tc.Failure.Text, "Grade=D") {
		t.Errorf("expected Grade=D in failure detail, got: %s", tc.Failure.Text)
	}
}

func TestWriteJUnit_WarningFail(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "mixed.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusWarning,
				TLSVersions: securityv1alpha1.TLSVersionSupport{
					TLS10: true,
					TLS12: true,
					TLS13: true,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJUnit(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	suite := suites.TestSuites[0]
	if suite.Failures != 1 {
		t.Errorf("expected 1 failure, got %d", suite.Failures)
	}
	tc := suite.TestCases[0]
	if tc.Failure == nil {
		t.Fatal("expected failure for warning endpoint")
	}
	if !strings.Contains(tc.Failure.Message, "Warning") {
		t.Errorf("expected Warning in failure message, got: %s", tc.Failure.Message)
	}
}

func TestWriteJUnit_MixedResults(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "good.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "bad.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindIngress,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "down.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindRoute,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusUnreachable,
				LastError:        "connection refused",
			},
		},
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "notls.example",
				Port:       80,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS,
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJUnit(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	suite := suites.TestSuites[0]
	if suite.Tests != 4 {
		t.Errorf("expected 4 tests, got %d", suite.Tests)
	}
	if suite.Failures != 3 {
		t.Errorf("expected 3 failures, got %d", suite.Failures)
	}

	// Verify the compliant one passes
	if suite.TestCases[0].Failure != nil {
		t.Error("expected first test case to pass")
	}
	// Verify unreachable has error text
	if suite.TestCases[2].Failure == nil {
		t.Fatal("expected failure for unreachable endpoint")
	}
	if suite.TestCases[2].Failure.Text != "connection refused" {
		t.Errorf("expected error text, got: %s", suite.TestCases[2].Failure.Text)
	}
}

func TestWriteJUnit_AllStatusTypes(t *testing.T) {
	statuses := []securityv1alpha1.ComplianceStatus{
		securityv1alpha1.ComplianceStatusCompliant,
		securityv1alpha1.ComplianceStatusNonCompliant,
		securityv1alpha1.ComplianceStatusWarning,
		securityv1alpha1.ComplianceStatusUnreachable,
		securityv1alpha1.ComplianceStatusTimeout,
		securityv1alpha1.ComplianceStatusClosed,
		securityv1alpha1.ComplianceStatusFiltered,
		securityv1alpha1.ComplianceStatusNoTLS,
		securityv1alpha1.ComplianceStatusPlaintextHTTP,
		securityv1alpha1.ComplianceStatusMutualTLSRequired,
		securityv1alpha1.ComplianceStatusPending,
		securityv1alpha1.ComplianceStatusUnknown,
	}

	reports := make([]securityv1alpha1.TLSComplianceReport, len(statuses))
	for i, s := range statuses {
		reports[i] = securityv1alpha1.TLSComplianceReport{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "test.example",
				Port:       int32(443 + i),
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: s,
			},
		}
	}

	var buf bytes.Buffer
	err := WriteJUnit(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	suite := suites.TestSuites[0]
	if suite.Tests != len(statuses) {
		t.Errorf("expected %d tests, got %d", len(statuses), suite.Tests)
	}

	// Only Compliant should pass
	passCount := 0
	for _, tc := range suite.TestCases {
		if tc.Failure == nil {
			passCount++
		}
	}
	if passCount != 1 {
		t.Errorf("expected exactly 1 passing test (Compliant), got %d", passCount)
	}
}

func TestWriteJUnit_TimeAttributes(t *testing.T) {
	tests := []struct {
		name              string
		reports           []securityv1alpha1.TLSComplianceReport
		expectCaseTime    string
		expectSuiteTime   string
		expectNoSuiteTime bool
	}{
		{
			name: "scan duration populates test case time",
			reports: []securityv1alpha1.TLSComplianceReport{
				{
					Spec: securityv1alpha1.TLSComplianceReportSpec{
						Host:       "timed.example",
						Port:       443,
						SourceKind: securityv1alpha1.SourceKindService,
					},
					Status: securityv1alpha1.TLSComplianceReportStatus{
						ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
						ScanDuration:     "1.5s",
					},
				},
			},
			expectCaseTime:  "1.500",
			expectSuiteTime: "1.500",
		},
		{
			name: "no scan duration omits time attribute",
			reports: []securityv1alpha1.TLSComplianceReport{
				{
					Spec: securityv1alpha1.TLSComplianceReportSpec{
						Host:       "notimed.example",
						Port:       443,
						SourceKind: securityv1alpha1.SourceKindService,
					},
					Status: securityv1alpha1.TLSComplianceReportStatus{
						ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
					},
				},
			},
			expectCaseTime:    "",
			expectNoSuiteTime: true,
		},
		{
			name: "invalid scan duration is ignored",
			reports: []securityv1alpha1.TLSComplianceReport{
				{
					Spec: securityv1alpha1.TLSComplianceReportSpec{
						Host:       "bad.example",
						Port:       443,
						SourceKind: securityv1alpha1.SourceKindService,
					},
					Status: securityv1alpha1.TLSComplianceReportStatus{
						ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
						ScanDuration:     "not-a-duration",
					},
				},
			},
			expectCaseTime:    "",
			expectNoSuiteTime: true,
		},
		{
			name: "suite time aggregates multiple reports",
			reports: []securityv1alpha1.TLSComplianceReport{
				{
					Spec: securityv1alpha1.TLSComplianceReportSpec{
						Host:       "a.example",
						Port:       443,
						SourceKind: securityv1alpha1.SourceKindService,
					},
					Status: securityv1alpha1.TLSComplianceReportStatus{
						ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
						ScanDuration:     "2s",
					},
				},
				{
					Spec: securityv1alpha1.TLSComplianceReportSpec{
						Host:       "b.example",
						Port:       443,
						SourceKind: securityv1alpha1.SourceKindService,
					},
					Status: securityv1alpha1.TLSComplianceReportStatus{
						ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
						ScanDuration:     "500ms",
					},
				},
			},
			expectSuiteTime: "2.500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteJUnit(&buf, tt.reports); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var suites JUnitTestSuites
			if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
				t.Fatalf("invalid XML: %v", err)
			}

			suite := suites.TestSuites[0]

			if tt.expectNoSuiteTime {
				if suite.Time != "" {
					t.Errorf("expected no suite time, got %q", suite.Time)
				}
			} else if tt.expectSuiteTime != "" {
				if suite.Time != tt.expectSuiteTime {
					t.Errorf("expected suite time %q, got %q", tt.expectSuiteTime, suite.Time)
				}
			}

			if tt.expectCaseTime != "" {
				if suite.TestCases[0].Time != tt.expectCaseTime {
					t.Errorf("expected case time %q, got %q", tt.expectCaseTime, suite.TestCases[0].Time)
				}
			} else if len(suite.TestCases) > 0 && len(tt.reports) == 1 {
				if suite.TestCases[0].Time != "" {
					t.Errorf("expected no case time, got %q", suite.TestCases[0].Time)
				}
			}
		})
	}
}

func TestWriteJUnit_ValidXML(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:       "test.example",
				Port:       443,
				SourceKind: securityv1alpha1.SourceKindService,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJUnit(&buf, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.HasPrefix(output, "<?xml") {
		t.Error("expected XML declaration at start")
	}
	if !strings.Contains(output, `name="TLS Compliance"`) {
		t.Error("expected test suite name")
	}
}
