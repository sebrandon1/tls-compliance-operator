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
	"sort"
	"strings"
	"time"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

var compliancePriority = map[securityv1alpha1.ComplianceStatus]int{
	securityv1alpha1.ComplianceStatusCompliant:         0,
	securityv1alpha1.ComplianceStatusWarning:           1,
	securityv1alpha1.ComplianceStatusNonCompliant:      2,
	securityv1alpha1.ComplianceStatusPlaintextHTTP:     3,
	securityv1alpha1.ComplianceStatusNoTLS:             4,
	securityv1alpha1.ComplianceStatusMutualTLSRequired: 5,
	securityv1alpha1.ComplianceStatusTimeout:           6,
	securityv1alpha1.ComplianceStatusClosed:            7,
	securityv1alpha1.ComplianceStatusFiltered:          8,
	securityv1alpha1.ComplianceStatusUnreachable:       9,
	securityv1alpha1.ComplianceStatusPending:           10,
	securityv1alpha1.ComplianceStatusUnknown:           11,
}

// SortReports sorts reports in place by the given key.
// Supported keys: host, port, compliance, expiry, grade, pqc.
// Unknown or empty keys are a no-op.
func SortReports(reports []securityv1alpha1.TLSComplianceReport, sortBy string) {
	switch strings.ToLower(sortBy) {
	case "host":
		sort.SliceStable(reports, func(i, j int) bool {
			return reports[i].Spec.Host < reports[j].Spec.Host
		})
	case "port":
		sort.SliceStable(reports, func(i, j int) bool {
			return reports[i].Spec.Port < reports[j].Spec.Port
		})
	case "compliance":
		sort.SliceStable(reports, func(i, j int) bool {
			return compliancePriority[reports[i].Status.ComplianceStatus] <
				compliancePriority[reports[j].Status.ComplianceStatus]
		})
	case "expiry":
		sort.SliceStable(reports, func(i, j int) bool {
			return certExpiry(&reports[i]).Before(certExpiry(&reports[j]))
		})
	case "grade":
		sort.SliceStable(reports, func(i, j int) bool {
			return emptyLast(reports[i].Status.OverallCipherGrade, reports[j].Status.OverallCipherGrade)
		})
	case "pqc":
		sort.SliceStable(reports, func(i, j int) bool {
			return emptyLast(string(reports[i].Status.PQCReadiness), string(reports[j].Status.PQCReadiness))
		})
	}
}

var distantFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

func certExpiry(r *securityv1alpha1.TLSComplianceReport) time.Time {
	if r.Status.CertificateInfo != nil && r.Status.CertificateInfo.NotAfter != nil {
		return r.Status.CertificateInfo.NotAfter.Time
	}
	return distantFuture
}

func emptyLast(a, b string) bool {
	if a == "" && b == "" {
		return false
	}
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	return a < b
}
