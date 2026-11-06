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
	"strings"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

// GroupsMode selects how the advertised groups are compared with the expected set.
type GroupsMode string

const (
	// GroupsModeContains requires the expected groups to be a subset of those advertised.
	GroupsModeContains GroupsMode = "contains"
	// GroupsModeExact requires set equality between expected and advertised groups.
	GroupsModeExact GroupsMode = "exact"
)

// ParseGroupsMode validates a --expected-groups-mode value. An empty string
// selects the default, contains.
func ParseGroupsMode(value string) (GroupsMode, error) {
	switch GroupsMode(strings.ToLower(strings.TrimSpace(value))) {
	case "", GroupsModeContains:
		return GroupsModeContains, nil
	case GroupsModeExact:
		return GroupsModeExact, nil
	default:
		return "", fmt.Errorf("invalid groups mode %q: must be contains or exact", value)
	}
}

// SplitGroups splits a comma-separated group list, trimming entries and
// dropping empty ones.
func SplitGroups(value string) []string {
	var groups []string
	for _, group := range strings.Split(value, ",") {
		if group = strings.TrimSpace(group); group != "" {
			groups = append(groups, group)
		}
	}
	return groups
}

// normalizeGroupName makes group names comparable across spellings:
// case-insensitive, and "-"/"_" insensitive. Profile names such as secp256r1
// are first mapped to Go's CurveID name so they compare against report data.
func normalizeGroupName(name string) string {
	goName := tlscheck.ProfileToGoCurve(strings.TrimSpace(name))
	goName = strings.ToLower(goName)
	goName = strings.ReplaceAll(goName, "-", "")
	goName = strings.ReplaceAll(goName, "_", "")
	return goName
}

// GroupCheck is the assertion result for one endpoint.
type GroupCheck struct {
	Endpoint   string
	Advertised []string
	Missing    []string
	Unexpected []string
	Skipped    bool
	SkipReason string
}

// Passed reports whether the endpoint satisfies the assertion. Skipped
// endpoints pass: their groups could not be enumerated, so there is nothing to
// assert against.
func (c *GroupCheck) Passed() bool {
	return c.Skipped || (len(c.Missing) == 0 && len(c.Unexpected) == 0)
}

// GroupsGateResult aggregates the assertion across a report set.
type GroupsGateResult struct {
	Mode     GroupsMode
	Expected []string
	Checked  int
	PassedN  int
	FailedN  int
	SkippedN int
	Failures []GroupCheck
	Skipped  []GroupCheck
}

// Passed reports whether every checked endpoint satisfied the assertion.
func (r *GroupsGateResult) Passed() bool {
	return r.FailedN == 0
}

// EvaluateExpectedGroups asserts the groups advertised by each scannable
// endpoint against expected.
//
// An endpoint is skipped when no groups were enumerated (no TLS, mTLS required,
// unreachable, TLS 1.2 only, or a scan that did not record curves). Skipped
// endpoints are listed so the result is never silent. An empty expected list
// disables the assertion and the gate passes with nothing checked.
func EvaluateExpectedGroups(
	reports []securityv1alpha1.TLSComplianceReport, expected []string, mode GroupsMode,
) GroupsGateResult {
	result := GroupsGateResult{Mode: mode, Expected: expected}
	if len(expected) == 0 {
		return result
	}

	wantSet := make(map[string]bool, len(expected))
	for _, group := range expected {
		wantSet[normalizeGroupName(group)] = true
	}

	for i := range reports {
		r := &reports[i]
		check := GroupCheck{
			Endpoint: net.JoinHostPort(r.Spec.Host, strconv.Itoa(int(r.Spec.Port))),
		}

		advertised := advertiseGroups(r)
		check.Advertised = advertised
		if len(advertised) == 0 {
			check.Skipped = true
			check.SkipReason = string(r.Status.ComplianceStatus)
			if check.SkipReason == "" {
				check.SkipReason = "no groups enumerated"
			}
			result.SkippedN++
			result.Skipped = append(result.Skipped, check)
			continue
		}

		gotSet := make(map[string]bool, len(advertised))
		for _, group := range advertised {
			gotSet[normalizeGroupName(group)] = true
		}

		for _, group := range expected {
			if !gotSet[normalizeGroupName(group)] {
				check.Missing = append(check.Missing, group)
			}
		}
		if mode == GroupsModeExact {
			for _, group := range advertised {
				if !wantSet[normalizeGroupName(group)] {
					check.Unexpected = append(check.Unexpected, group)
				}
			}
		}

		result.Checked++
		if check.Passed() {
			result.PassedN++
			continue
		}
		result.FailedN++
		result.Failures = append(result.Failures, check)
	}

	sort.Slice(result.Failures, func(i, j int) bool { return result.Failures[i].Endpoint < result.Failures[j].Endpoint })
	sort.Slice(result.Skipped, func(i, j int) bool { return result.Skipped[i].Endpoint < result.Skipped[j].Endpoint })
	return result
}

// advertiseGroups returns the unique humans-readable group names an endpoint
// advertised, in a stable order.
func advertiseGroups(r *securityv1alpha1.TLSComplianceReport) []string {
	if len(r.Status.NegotiatedCurves) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(r.Status.NegotiatedCurves))
	var groups []string
	for _, curve := range r.Status.NegotiatedCurves {
		if curve == "" {
			continue
		}
		key := normalizeGroupName(curve)
		if seen[key] {
			continue
		}
		seen[key] = true
		groups = append(groups, curve)
	}
	sort.Strings(groups)
	return groups
}

// WriteGroupsGate writes a human-readable assertion report to w.
func WriteGroupsGate(w io.Writer, result *GroupsGateResult) error {
	ew := &errWriter{w: w}

	ew.printf("Expected Groups (%s)\n", result.Mode)
	ew.printf("-----------------------\n")
	if len(result.Expected) == 0 {
		ew.printf("  no expectation configured; nothing checked\n")
		return ew.err
	}
	ew.printf("  Expected:\t%s\n", strings.Join(result.Expected, ", "))
	ew.printf("  Checked:\t%d\n", result.Checked)
	ew.printf("  Passed:\t%d\n", result.PassedN)
	ew.printf("  Failed:\t%d\n", result.FailedN)
	ew.printf("  Skipped:\t%d\n", result.SkippedN)

	for _, failure := range result.Failures {
		ew.printf("\n  %s\n", failure.Endpoint)
		if len(failure.Missing) > 0 {
			ew.printf("    missing:\t%s\n", strings.Join(failure.Missing, ", "))
		}
		if len(failure.Unexpected) > 0 {
			ew.printf("    unexpected:\t%s\n", strings.Join(failure.Unexpected, ", "))
		}
	}
	if len(result.Skipped) > 0 {
		ew.printf("\nSkipped (no groups enumerated):\n")
		for _, skipped := range result.Skipped {
			ew.printf("  %s (%s)\n", skipped.Endpoint, skipped.SkipReason)
		}
	}

	return ew.err
}
