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
	"strconv"
	"strings"
	"time"

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
	// PQCStatus filters by PQC readiness level (case-insensitive).
	PQCStatus string
	// ExpiresWithin filters to certificates expiring within a duration (e.g. "30d", "7d").
	ExpiresWithin string
	// Expired filters to only expired certificates.
	Expired bool
	// Issuer filters by certificate issuer (case-insensitive substring match).
	Issuer string
	// Subject filters by certificate subject (case-insensitive substring match).
	Subject string
	// TLSVersion filters to reports supporting a specific TLS version (e.g. "1.3", "1.2", "1.0", "1.1", "ssl3.0").
	TLSVersion string
	// Grade filters by exact cipher grade (case-insensitive: A, B, C, D, F).
	Grade string
	// MinGrade filters to reports with a grade at or above this threshold (e.g. "B" shows A and B).
	MinGrade string
}

var gradeRank = map[string]int{
	"A": 0, "B": 1, "C": 2, "D": 3, "F": 4,
}

// IsEmpty returns true if no filters are set.
func (o *FilterOptions) IsEmpty() bool {
	return o.Namespace == "" && o.Status == "" && o.Source == "" &&
		o.PQCStatus == "" && o.ExpiresWithin == "" && !o.Expired &&
		o.Issuer == "" && o.Subject == "" && o.TLSVersion == "" &&
		o.Grade == "" && o.MinGrade == ""
}

// FilterReports returns the subset of reports matching all non-empty filter criteria.
// Filters are combined with AND logic. Empty filters are pass-through.
// Returns an error if ExpiresWithin contains an unparseable duration.
func FilterReports(reports []securityv1alpha1.TLSComplianceReport, opts *FilterOptions) ([]securityv1alpha1.TLSComplianceReport, error) {
	if opts.IsEmpty() {
		return reports, nil
	}

	var expiresWithin time.Duration
	if opts.ExpiresWithin != "" {
		var err error
		expiresWithin, err = ParseExpiresWithin(opts.ExpiresWithin)
		if err != nil {
			return nil, fmt.Errorf("invalid --expires-within value %q: %w", opts.ExpiresWithin, err)
		}
	}

	now := time.Now()
	filtered := make([]securityv1alpha1.TLSComplianceReport, 0, len(reports))
	for i := range reports {
		if matchesFilter(&reports[i], opts, now, expiresWithin) {
			filtered = append(filtered, reports[i])
		}
	}

	return filtered, nil
}

// ParseExpiresWithin parses a duration string like "30d", "7d", or "90d" into a time.Duration.
func ParseExpiresWithin(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}

	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid day count: %w", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}

func matchesFilter(r *securityv1alpha1.TLSComplianceReport, opts *FilterOptions, now time.Time, expiresWithin time.Duration) bool {
	if opts.Namespace != "" && r.Spec.SourceNamespace != opts.Namespace {
		return false
	}
	if opts.Status != "" && !strings.EqualFold(string(r.Status.ComplianceStatus), opts.Status) {
		return false
	}
	if opts.Source != "" && !strings.EqualFold(string(r.Spec.SourceKind), opts.Source) {
		return false
	}
	if opts.PQCStatus != "" && !strings.EqualFold(string(r.Status.PQCReadiness), opts.PQCStatus) {
		return false
	}
	if opts.Expired {
		if r.Status.CertificateInfo == nil || !r.Status.CertificateInfo.IsExpired {
			return false
		}
	}
	if opts.ExpiresWithin != "" {
		if r.Status.CertificateInfo == nil || r.Status.CertificateInfo.NotAfter == nil {
			return false
		}
		expiry := r.Status.CertificateInfo.NotAfter.Time
		if expiry.Before(now) || expiry.After(now.Add(expiresWithin)) {
			return false
		}
	}
	if opts.Issuer != "" {
		if r.Status.CertificateInfo == nil || !strings.Contains(strings.ToLower(r.Status.CertificateInfo.Issuer), strings.ToLower(opts.Issuer)) {
			return false
		}
	}
	if opts.Subject != "" {
		if r.Status.CertificateInfo == nil || !strings.Contains(strings.ToLower(r.Status.CertificateInfo.Subject), strings.ToLower(opts.Subject)) {
			return false
		}
	}
	if opts.TLSVersion != "" && !matchesTLSVersion(r, opts.TLSVersion) {
		return false
	}
	if opts.Grade != "" && !strings.EqualFold(r.Status.OverallCipherGrade, opts.Grade) {
		return false
	}
	if opts.MinGrade != "" && !meetsMinGrade(r.Status.OverallCipherGrade, opts.MinGrade) {
		return false
	}

	return true
}

func meetsMinGrade(actual, minGrade string) bool {
	actualRank, aOK := gradeRank[strings.ToUpper(actual)]
	minRank, mOK := gradeRank[strings.ToUpper(minGrade)]
	if !aOK || !mOK {
		return false
	}
	return actualRank <= minRank
}

func matchesTLSVersion(r *securityv1alpha1.TLSComplianceReport, version string) bool {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "1.3", "tls1.3":
		return r.Status.TLSVersions.TLS13
	case "1.2", "tls1.2":
		return r.Status.TLSVersions.TLS12
	case "1.1", "tls1.1":
		return r.Status.TLSVersions.TLS11
	case "1.0", "tls1.0":
		return r.Status.TLSVersions.TLS10
	case "ssl3.0", "ssl30", "3.0":
		return r.Status.TLSVersions.SSL30
	default:
		return false
	}
}
