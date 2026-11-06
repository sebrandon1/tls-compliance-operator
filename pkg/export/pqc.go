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
		verdict, reason := classifyPQC(r)
		switch verdict {
		case pqcSkipped:
			result.Skipped++
			result.SkippedReports = append(result.SkippedReports, fmt.Sprintf("%s (%s)", endpointName(r), reason))
		case pqcReady:
			result.Ready++
		case pqcNotReady:
			result.NotReady++
			result.NotReadyReports = append(result.NotReadyReports, fmt.Sprintf("%s (%s)", endpointName(r), reason))
		}
	}

	sort.Strings(result.NotReadyReports)
	sort.Strings(result.SkippedReports)
	return result
}

// pqcVerdict classifies a report for the PQC gate.
type pqcVerdict int

const (
	pqcReady pqcVerdict = iota
	pqcNotReady
	pqcSkipped
)

// classifyPQC applies the gate's rules to one report. It is the single
// implementation of the gate, shared by the aggregate result and the JUnit
// export so the two can never disagree. The reason is empty for pqcReady.
func classifyPQC(r *securityv1alpha1.TLSComplianceReport) (pqcVerdict, string) {
	if UnscannableStatuses[r.Status.ComplianceStatus] {
		return pqcSkipped, string(r.Status.ComplianceStatus)
	}
	if r.Status.PQCReadiness == securityv1alpha1.PQCReadinessNoPQC {
		return pqcSkipped, string(r.Status.PQCReadiness)
	}
	if r.Status.PQCReadiness == securityv1alpha1.PQCReadinessPQCReady {
		return pqcReady, ""
	}

	readiness := string(r.Status.PQCReadiness)
	if readiness == "" {
		readiness = "Unknown"
	}
	return pqcNotReady, readiness
}

// pqcGateFailures returns, per report index, the readiness that fails the PQC
// gate. Skipped endpoints are absent: the gate does not assert on them.
func pqcGateFailures(reports []securityv1alpha1.TLSComplianceReport) map[int]string {
	failures := make(map[int]string)
	for i := range reports {
		if verdict, reason := classifyPQC(&reports[i]); verdict == pqcNotReady {
			failures[i] = reason
		}
	}
	return failures
}

func endpointName(r *securityv1alpha1.TLSComplianceReport) string {
	return net.JoinHostPort(r.Spec.Host, strconv.Itoa(int(r.Spec.Port)))
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
