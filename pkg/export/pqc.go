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
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// UnscannableStatuses are ComplianceStatus values for endpoints where a TLS
// handshake never produced a result. The PQC gate skips them rather than
// failing: an endpoint that could not be probed says nothing about its
// post-quantum readiness. This mirrors openshift/tls-scanner's
// SkipUnscannable behavior.
//
// PlaintextHTTP is included because the endpoint serves cleartext HTTP and is
// already caught by --fail-on-non-compliant; failing it again here would make
// the PQC gate a general compliance gate.
var UnscannableStatuses = map[securityv1alpha1.ComplianceStatus]bool{
	securityv1alpha1.ComplianceStatusTimeout:           true,
	securityv1alpha1.ComplianceStatusUnreachable:       true,
	securityv1alpha1.ComplianceStatusClosed:            true,
	securityv1alpha1.ComplianceStatusFiltered:          true,
	securityv1alpha1.ComplianceStatusMutualTLSRequired: true,
	securityv1alpha1.ComplianceStatusPending:           true,
	securityv1alpha1.ComplianceStatusUnknown:           true,
	securityv1alpha1.ComplianceStatusPlaintextHTTP:     true,
}

// PQCGateResult is the outcome of evaluating the PQC-only gate over a set of
// reports. Skipped endpoints are counted so a gate run is never silent about
// what it did not evaluate.
type PQCGateResult struct {
	Ready    int
	NotReady int
	Skipped  int
	// NotReadyReports names each failing endpoint as "host:port (readiness)".
	NotReadyReports []string
	// SkippedReports names each skipped endpoint as "host:port (reason)".
	SkippedReports []string
}

// Passed reports whether the gate allows a zero exit code. It is true when no
// scannable endpoint is short of PQCReady.
func (r PQCGateResult) Passed() bool {
	return r.NotReady == 0
}

// EvaluatePQCGate classifies every report as ready, not ready, or skipped.
//
// An endpoint is skipped when its ComplianceStatus is one of
// UnscannableStatuses, or when its PQCReadiness is NoPQC (no TLS was detected,
// so post-quantum readiness is not a meaningful assertion). Everything else
// passes only when PQCReadiness is PQCReady.
func EvaluatePQCGate(reports []securityv1alpha1.TLSComplianceReport) PQCGateResult {
	var result PQCGateResult

	for i := range reports {
		r := &reports[i]
		endpoint := net.JoinHostPort(r.Spec.Host, strconv.Itoa(int(r.Spec.Port)))

		reason := string(r.Status.ComplianceStatus)
		if UnscannableStatuses[r.Status.ComplianceStatus] {
			result.Skipped++
			result.SkippedReports = append(result.SkippedReports, fmt.Sprintf("%s (%s)", endpoint, reason))
			continue
		}

		if r.Status.PQCReadiness == securityv1alpha1.PQCReadinessNoPQC {
			result.Skipped++
			result.SkippedReports = append(result.SkippedReports, fmt.Sprintf("%s (%s)", endpoint, r.Status.PQCReadiness))
			continue
		}

		if r.Status.PQCReadiness == securityv1alpha1.PQCReadinessPQCReady {
			result.Ready++
			continue
		}

		readiness := string(r.Status.PQCReadiness)
		if readiness == "" {
			readiness = "Unknown"
		}
		result.NotReady++
		result.NotReadyReports = append(result.NotReadyReports, fmt.Sprintf("%s (%s)", endpoint, readiness))
	}

	sort.Strings(result.NotReadyReports)
	sort.Strings(result.SkippedReports)
	return result
}

// WritePQCGate writes a human-readable PQC gate report: the three counts and,
// when the gate fails, the endpoints responsible.
func WritePQCGate(w io.Writer, result PQCGateResult) error {
	ew := &errWriter{w: w}

	ew.printf("PQC Gate\n")
	ew.printf("--------\n")
	ew.printf("  Ready:\t%d\n", result.Ready)
	ew.printf("  Not Ready:\t%d\n", result.NotReady)
	ew.printf("  Skipped:\t%d\n", result.Skipped)

	if len(result.NotReadyReports) > 0 {
		ew.printf("\nNot PQC-ready endpoints:\n")
		for _, endpoint := range result.NotReadyReports {
			ew.printf("  %s\n", endpoint)
		}
	}
	if len(result.SkippedReports) > 0 {
		ew.printf("\nSkipped (unscannable) endpoints:\n")
		for _, endpoint := range result.SkippedReports {
			ew.printf("  %s\n", endpoint)
		}
	}

	return ew.err
}
