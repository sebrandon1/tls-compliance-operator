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
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func makeReport(status securityv1alpha1.ComplianceStatus) securityv1alpha1.TLSComplianceReport {
	return securityv1alpha1.TLSComplianceReport{
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: status,
		},
	}
}

func TestHasNonCompliantReports(t *testing.T) {
	tests := []struct {
		name     string
		reports  []securityv1alpha1.TLSComplianceReport
		expected bool
	}{
		{
			name:     "empty slice",
			reports:  nil,
			expected: false,
		},
		{
			name:     "all compliant",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusCompliant)},
			expected: false,
		},
		{
			name:     "NonCompliant triggers",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusNonCompliant)},
			expected: true,
		},
		{
			name:     "NoTLS triggers",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusNoTLS)},
			expected: true,
		},
		{
			name:     "PlaintextHTTP triggers",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusPlaintextHTTP)},
			expected: true,
		},
		{
			name: "compliant plus timeout does not trigger",
			reports: []securityv1alpha1.TLSComplianceReport{
				makeReport(securityv1alpha1.ComplianceStatusCompliant),
				makeReport(securityv1alpha1.ComplianceStatusTimeout),
			},
			expected: false,
		},
		{
			name: "compliant plus non-compliant triggers",
			reports: []securityv1alpha1.TLSComplianceReport{
				makeReport(securityv1alpha1.ComplianceStatusCompliant),
				makeReport(securityv1alpha1.ComplianceStatusNonCompliant),
			},
			expected: true,
		},
		{
			name:     "Timeout alone does not trigger",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusTimeout)},
			expected: false,
		},
		{
			name:     "Unreachable alone does not trigger",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusUnreachable)},
			expected: false,
		},
		{
			name:     "Pending alone does not trigger",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusPending)},
			expected: false,
		},
		{
			name:     "MutualTLSRequired does not trigger",
			reports:  []securityv1alpha1.TLSComplianceReport{makeReport(securityv1alpha1.ComplianceStatusMutualTLSRequired)},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HasNonCompliantReports(tc.reports)
			if got != tc.expected {
				t.Errorf("HasNonCompliantReports() = %v, want %v", got, tc.expected)
			}
		})
	}
}
