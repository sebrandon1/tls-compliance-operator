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
	"encoding/xml"
	"fmt"
	"io"
	"strconv"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// JUnitTestSuites is the top-level JUnit XML element.
type JUnitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite represents a single test suite.
type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a single test case.
type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

// JUnitFailure represents a test failure.
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// WriteJUnit writes TLSComplianceReport items as JUnit XML to the given writer.
func WriteJUnit(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	var failures int
	cases := make([]JUnitTestCase, 0, len(reports))

	for i := range reports {
		tc := reportToTestCase(&reports[i])
		if tc.Failure != nil {
			failures++
		}
		cases = append(cases, tc)
	}

	suites := JUnitTestSuites{
		TestSuites: []JUnitTestSuite{
			{
				Name:      "TLS Compliance",
				Tests:     len(cases),
				Failures:  failures,
				TestCases: cases,
			},
		},
	}

	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		return fmt.Errorf("writing XML header: %w", err)
	}

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return fmt.Errorf("encoding JUnit XML: %w", err)
	}

	return nil
}

func reportToTestCase(r *securityv1alpha1.TLSComplianceReport) JUnitTestCase {
	name := r.Spec.Host + ":" + strconv.Itoa(int(r.Spec.Port))
	tc := JUnitTestCase{
		Name:      name,
		ClassName: string(r.Spec.SourceKind),
	}

	switch r.Status.ComplianceStatus {
	case securityv1alpha1.ComplianceStatusCompliant:
		// pass — no failure
	case securityv1alpha1.ComplianceStatusNonCompliant:
		tc.Failure = &JUnitFailure{
			Message: "NonCompliant: supports deprecated TLS versions",
			Text:    failureDetail(r),
		}
	case securityv1alpha1.ComplianceStatusWarning:
		tc.Failure = &JUnitFailure{
			Message: "Warning: TLS 1.3 not supported",
			Text:    failureDetail(r),
		}
	case securityv1alpha1.ComplianceStatusUnreachable,
		securityv1alpha1.ComplianceStatusTimeout,
		securityv1alpha1.ComplianceStatusClosed,
		securityv1alpha1.ComplianceStatusFiltered:
		tc.Failure = &JUnitFailure{
			Message: string(r.Status.ComplianceStatus) + ": endpoint not reachable",
			Text:    r.Status.LastError,
		}
	case securityv1alpha1.ComplianceStatusNoTLS:
		tc.Failure = &JUnitFailure{
			Message: "NoTLS: port does not speak TLS",
		}
	case securityv1alpha1.ComplianceStatusMutualTLSRequired:
		tc.Failure = &JUnitFailure{
			Message: "MutualTLSRequired: server requires client certificate",
		}
	default:
		tc.Failure = &JUnitFailure{
			Message: string(r.Status.ComplianceStatus) + ": check incomplete",
		}
	}

	return tc
}

func failureDetail(r *securityv1alpha1.TLSComplianceReport) string {
	detail := fmt.Sprintf("TLS 1.0=%v TLS 1.1=%v TLS 1.2=%v TLS 1.3=%v",
		r.Status.TLSVersions.TLS10,
		r.Status.TLSVersions.TLS11,
		r.Status.TLSVersions.TLS12,
		r.Status.TLSVersions.TLS13)
	if r.Status.OverallCipherGrade != "" {
		detail += " Grade=" + r.Status.OverallCipherGrade
	}
	return detail
}
