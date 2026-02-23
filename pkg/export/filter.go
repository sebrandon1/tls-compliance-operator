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
	"strings"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// FilterOptions specifies criteria for filtering TLSComplianceReports.
type FilterOptions struct {
	// Namespace filters by source namespace (exact match).
	Namespace string
	// Status filters by compliance status (case-insensitive).
	Status string
	// Source filters by source kind (case-insensitive).
	Source string
}

// FilterReports returns the subset of reports matching all non-empty filter criteria.
// Filters are combined with AND logic. Empty filters are pass-through.
func FilterReports(reports []securityv1alpha1.TLSComplianceReport, opts FilterOptions) []securityv1alpha1.TLSComplianceReport {
	if opts.Namespace == "" && opts.Status == "" && opts.Source == "" {
		return reports
	}

	filtered := make([]securityv1alpha1.TLSComplianceReport, 0, len(reports))
	for i := range reports {
		if matchesFilter(&reports[i], opts) {
			filtered = append(filtered, reports[i])
		}
	}

	return filtered
}

func matchesFilter(r *securityv1alpha1.TLSComplianceReport, opts FilterOptions) bool {
	if opts.Namespace != "" && r.Spec.SourceNamespace != opts.Namespace {
		return false
	}
	if opts.Status != "" && !strings.EqualFold(string(r.Status.ComplianceStatus), opts.Status) {
		return false
	}
	if opts.Source != "" && !strings.EqualFold(string(r.Spec.SourceKind), opts.Source) {
		return false
	}

	return true
}
