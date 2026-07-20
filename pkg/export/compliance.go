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
	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// NonCompliantStatuses are ComplianceStatus values that indicate a definite
// compliance failure. Infrastructure statuses (Timeout, Unreachable) and
// incomplete statuses (Pending, Unknown) are excluded to avoid CI flakiness.
var NonCompliantStatuses = map[securityv1alpha1.ComplianceStatus]bool{
	securityv1alpha1.ComplianceStatusNonCompliant:  true,
	securityv1alpha1.ComplianceStatusNoTLS:         true,
	securityv1alpha1.ComplianceStatusPlaintextHTTP: true,
}

// HasNonCompliantReports returns true if any report has a ComplianceStatus
// that is definitively non-compliant.
func HasNonCompliantReports(reports []securityv1alpha1.TLSComplianceReport) bool {
	for i := range reports {
		if NonCompliantStatuses[reports[i].Status.ComplianceStatus] {
			return true
		}
	}
	return false
}
