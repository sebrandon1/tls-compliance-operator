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
	"text/tabwriter"
	"time"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// knownStatuses defines the deterministic order for status output.
var knownStatuses = []securityv1alpha1.ComplianceStatus{
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

// knownSourceKinds defines the deterministic order for source kind output.
var knownSourceKinds = []securityv1alpha1.SourceKind{
	securityv1alpha1.SourceKindService,
	securityv1alpha1.SourceKindIngress,
	securityv1alpha1.SourceKindRoute,
	securityv1alpha1.SourceKindTarget,
	securityv1alpha1.SourceKindPod,
}

// Summary holds aggregated statistics for a set of TLS compliance reports.
type Summary struct {
	Total             int
	ByStatus          map[securityv1alpha1.ComplianceStatus]int
	BySourceKind      map[securityv1alpha1.SourceKind]int
	CompliancePercent float64
	CertExpired       int
	CertExpiring7d    int
	CertExpiring30d   int
	CertExpiring90d   int
}

// ComputeSummary calculates summary statistics from a slice of reports.
// The now parameter is used for certificate expiry calculations.
func ComputeSummary(reports []securityv1alpha1.TLSComplianceReport, now time.Time) Summary {
	s := Summary{
		Total:        len(reports),
		ByStatus:     make(map[securityv1alpha1.ComplianceStatus]int),
		BySourceKind: make(map[securityv1alpha1.SourceKind]int),
	}

	for i := range reports {
		r := &reports[i]
		s.ByStatus[r.Status.ComplianceStatus]++
		s.BySourceKind[r.Spec.SourceKind]++

		if r.Status.CertificateInfo != nil && r.Status.CertificateInfo.NotAfter != nil {
			expiry := r.Status.CertificateInfo.NotAfter.Time
			daysUntil := expiry.Sub(now).Hours() / 24

			switch {
			case daysUntil < 0:
				s.CertExpired++
			case daysUntil < 7:
				s.CertExpiring7d++
			case daysUntil < 30:
				s.CertExpiring30d++
			case daysUntil < 90:
				s.CertExpiring90d++
			}
		}
	}

	if s.Total > 0 {
		compliant := s.ByStatus[securityv1alpha1.ComplianceStatusCompliant]
		s.CompliancePercent = float64(compliant) / float64(s.Total) * 100
	}

	return s
}

// errWriter wraps an io.Writer and captures the first write error.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...interface{}) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// WriteSummary writes a human-readable summary to the given writer.
func WriteSummary(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	s := ComputeSummary(reports, time.Now())

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	ew := &errWriter{w: tw}

	ew.printf("TLS Compliance Summary\n")
	ew.printf("======================\n\n")
	ew.printf("Total Endpoints:\t%d\n", s.Total)
	ew.printf("Compliance Rate:\t%.1f%%\n\n", s.CompliancePercent)

	ew.printf("Status Breakdown\n")
	ew.printf("----------------\n")
	for _, status := range knownStatuses {
		count := s.ByStatus[status]
		if count > 0 {
			ew.printf("  %s:\t%d\n", status, count)
		}
	}

	ew.printf("\nSource Kind Breakdown\n")
	ew.printf("---------------------\n")
	for _, kind := range knownSourceKinds {
		count := s.BySourceKind[kind]
		if count > 0 {
			ew.printf("  %s:\t%d\n", kind, count)
		}
	}

	if s.CertExpired > 0 || s.CertExpiring7d > 0 || s.CertExpiring30d > 0 || s.CertExpiring90d > 0 {
		ew.printf("\nCertificate Expiry\n")
		ew.printf("------------------\n")
		if s.CertExpired > 0 {
			ew.printf("  Expired:\t%d\n", s.CertExpired)
		}
		if s.CertExpiring7d > 0 {
			ew.printf("  Expiring < 7 days:\t%d\n", s.CertExpiring7d)
		}
		if s.CertExpiring30d > 0 {
			ew.printf("  Expiring < 30 days:\t%d\n", s.CertExpiring30d)
		}
		if s.CertExpiring90d > 0 {
			ew.printf("  Expiring < 90 days:\t%d\n", s.CertExpiring90d)
		}
	}

	if ew.err != nil {
		return ew.err
	}

	return tw.Flush()
}
