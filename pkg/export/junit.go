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
	"net"
	"strconv"
	"strings"
	"time"

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
	Time      string          `xml:"time,attr,omitempty"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a single test case.
type JUnitTestCase struct {
	XMLName    xml.Name        `xml:"testcase"`
	Name       string          `xml:"name,attr"`
	ClassName  string          `xml:"classname,attr"`
	Time       string          `xml:"time,attr,omitempty"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	Failure    *JUnitFailure   `xml:"failure,omitempty"`
}

// JUnitProperty is a single testcase property.
type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// JUnitAdherenceTag marks cases that assert TLS profile adherence, using the
// same tag upstream tls-scanner emits so existing gate tooling recognizes them.
const JUnitAdherenceTag = "[OCPFeatureGate:TLSAdherence]"

// JUnitFailure represents a test failure.
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// JUnitOptions carries the CI gates whose verdicts should appear in the report.
// Without them a gate failure is visible only as a process exit code, so a CI
// system reading the JUnit shows the endpoint as passing.
type JUnitOptions struct {
	// RequirePQC marks endpoints that are not PQCReady as failures.
	RequirePQC bool
	// ExpectedGroups asserts advertised TLS named groups. Empty disables it.
	ExpectedGroups []string
	// GroupsMode selects how ExpectedGroups is compared.
	GroupsMode GroupsMode
}

// WriteJUnit writes TLSComplianceReport items as JUnit XML to the given writer.
func WriteJUnit(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	return WriteJUnitWithOptions(w, reports, JUnitOptions{})
}

// WriteJUnitWithOptions writes JUnit XML, reflecting the enabled CI gates as
// testcase failures. Endpoints the gates skip are left alone: nothing was
// asserted about them.
func WriteJUnitWithOptions(
	w io.Writer, reports []securityv1alpha1.TLSComplianceReport, opts JUnitOptions,
) error {
	var failures int
	var totalDuration time.Duration
	cases := make([]JUnitTestCase, 0, len(reports))
	seenNames := make(map[string]int, len(reports))
	gateFailures := gateFailuresByReport(reports, opts)

	for i := range reports {
		tc := reportToTestCase(&reports[i])
		// A compliance failure is already reported; the gate verdict would add
		// detail to a case that is failing either way.
		if tc.Failure == nil {
			if gateFailure := gateFailures[i]; gateFailure != nil {
				tc.Failure = gateFailure
			}
		}
		makeUniqueCaseName(&tc, seenNames)
		if tc.Failure != nil {
			failures++
		}
		if tc.Time != "" {
			if d, err := time.ParseDuration(reports[i].Status.ScanDuration); err == nil {
				totalDuration += d
			}
		}
		cases = append(cases, tc)
	}

	suite := JUnitTestSuite{
		Name:      "TLS Compliance",
		Tests:     len(cases),
		Failures:  failures,
		TestCases: cases,
	}
	if totalDuration > 0 {
		suite.Time = formatJUnitTime(totalDuration)
	}

	suites := JUnitTestSuites{
		TestSuites: []JUnitTestSuite{suite},
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

// gateFailuresByReport maps a report index to the failure the enabled gates
// raise against it. Both gates can fire on the same endpoint, so their messages
// are combined rather than one masking the other.
func gateFailuresByReport(
	reports []securityv1alpha1.TLSComplianceReport, opts JUnitOptions,
) map[int]*JUnitFailure {
	var pqcFailures map[int]string
	if opts.RequirePQC {
		pqcFailures = pqcGateFailures(reports)
	}
	var groupFailures map[int]GroupCheck
	if len(opts.ExpectedGroups) > 0 {
		groupFailures = groupGateFailures(reports, opts.ExpectedGroups, opts.GroupsMode)
	}

	failures := make(map[int]*JUnitFailure)
	for i := range reports {
		var messages, details []string

		if readiness, ok := pqcFailures[i]; ok {
			messages = append(messages, fmt.Sprintf("PQC gate: %s (want PQCReady)", readiness))
			details = append(details, fmt.Sprintf(
				"%s is %s; the gate requires PQCReady (TLS 1.3 with ML-KEM)", endpointName(&reports[i]), readiness))
		}

		if check, ok := groupFailures[i]; ok {
			messages = append(messages, groupFailureMessage(&check))
			details = append(details, groupFailureDetail(&check))
		}

		if len(messages) > 0 {
			failures[i] = &JUnitFailure{
				Message: strings.Join(messages, "; "),
				Text:    strings.Join(details, "\n"),
			}
		}
	}
	return failures
}

func groupFailureMessage(check *GroupCheck) string {
	var parts []string
	if len(check.Missing) > 0 {
		parts = append(parts, "missing "+strings.Join(check.Missing, ", "))
	}
	if len(check.Unexpected) > 0 {
		parts = append(parts, "unexpected "+strings.Join(check.Unexpected, ", "))
	}
	return "Expected groups: " + strings.Join(parts, "; ")
}

func groupFailureDetail(check *GroupCheck) string {
	advertised := strings.Join(check.Advertised, ", ")
	if advertised == "" {
		advertised = "none"
	}
	return fmt.Sprintf("%s advertised: %s", check.Endpoint, advertised)
}

// CaseName builds the stable, workload-keyed name for a report:
// "ns/<namespace> <kind>/<name> port/<port>". Pod sources use the owning
// workload recorded at scan time, so recreating a pod does not rename the case.
func CaseName(r *securityv1alpha1.TLSComplianceReport) string {
	kind := string(r.Spec.SourceKind)
	name := r.Spec.SourceName
	if r.Status.WorkloadKind != "" {
		kind = r.Status.WorkloadKind
		name = r.Status.WorkloadName
	}

	var b strings.Builder
	if r.Spec.SourceNamespace != "" {
		b.WriteString("ns/")
		b.WriteString(r.Spec.SourceNamespace)
		b.WriteString(" ")
	}
	b.WriteString(kind)
	b.WriteString("/")
	b.WriteString(name)
	b.WriteString(" port/")
	b.WriteString(strconv.Itoa(int(r.Spec.Port)))
	return b.String()
}

// assertsAdherence reports whether the report carries a TLS profile compliance
// result, meaning the case asserts profile adherence.
func assertsAdherence(r *securityv1alpha1.TLSComplianceReport) bool {
	return r.Status.APIServerProfileCompliance != nil ||
		r.Status.IngressProfileCompliance != nil ||
		r.Status.KubeletProfileCompliance != nil
}

// makeUniqueCaseName disambiguates duplicate names (one workload exposing the
// same port through several endpoints) by appending " #2", " #3", ...
func makeUniqueCaseName(tc *JUnitTestCase, seen map[string]int) {
	seen[tc.Name]++
	if n := seen[tc.Name]; n > 1 {
		tc.Name = fmt.Sprintf("%s #%d", tc.Name, n)
	}
}

func reportToTestCase(r *securityv1alpha1.TLSComplianceReport) JUnitTestCase {
	name := CaseName(r)
	if assertsAdherence(r) {
		name += " " + JUnitAdherenceTag
	}
	tc := JUnitTestCase{
		Name:       name,
		ClassName:  string(r.Spec.SourceKind),
		Properties: junitProperties(r),
	}

	if r.Status.ScanDuration != "" {
		if d, err := time.ParseDuration(r.Status.ScanDuration); err == nil {
			tc.Time = formatJUnitTime(d)
		}
	}

	switch r.Status.ComplianceStatus {
	case securityv1alpha1.ComplianceStatusCompliant:
		// pass — no failure
	case securityv1alpha1.ComplianceStatusLocalhostOnly:
		// pass — the listener is intentionally bound to loopback, so the pod IP
		// probe cannot reach it but the endpoint is not a compliance failure.
	case securityv1alpha1.ComplianceStatusNonCompliant:
		tc.Failure = &JUnitFailure{
			Message: "NonCompliant: supports deprecated TLS versions",
			Text:    failureDetail(r),
		}
	case securityv1alpha1.ComplianceStatusWarning:
		tc.Failure = &JUnitFailure{
			Message: "Warning: endpoint supports modern TLS but also allows legacy versions",
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
	case securityv1alpha1.ComplianceStatusPlaintextHTTP:
		tc.Failure = &JUnitFailure{
			Message: "PlaintextHTTP: endpoint serves unencrypted HTTP",
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

// junitProperties keeps per-endpoint detail out of the case name.
func junitProperties(r *securityv1alpha1.TLSComplianceReport) []JUnitProperty {
	props := []JUnitProperty{
		{Name: "endpoint", Value: net.JoinHostPort(r.Spec.Host, strconv.Itoa(int(r.Spec.Port)))},
		{Name: "complianceStatus", Value: string(r.Status.ComplianceStatus)},
	}
	if r.Status.OverallCipherGrade != "" {
		props = append(props, JUnitProperty{Name: "cipherGrade", Value: r.Status.OverallCipherGrade})
	}
	if r.Status.PQCReadiness != "" {
		props = append(props, JUnitProperty{Name: "pqcReadiness", Value: string(r.Status.PQCReadiness)})
	}
	if r.Status.CertificateInfo != nil && r.Status.CertificateInfo.NotAfter != nil {
		props = append(props, JUnitProperty{
			Name:  "certNotAfter",
			Value: r.Status.CertificateInfo.NotAfter.UTC().Format(time.RFC3339),
		})
	}
	return props
}

// formatJUnitTime formats a duration as seconds with three decimal places,
// matching the JUnit XML convention (e.g. "1.234").
func formatJUnitTime(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', 3, 64)
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
