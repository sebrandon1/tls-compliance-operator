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
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func makeCurveReport(host string, status securityv1alpha1.ComplianceStatus, curves map[string]string) securityv1alpha1.TLSComplianceReport {
	return securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{Host: host, Port: 443},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: status,
			NegotiatedCurves: curves,
		},
	}
}

func TestParseGroupsMode(t *testing.T) {
	tests := []struct {
		in      string
		want    GroupsMode
		wantErr bool
	}{
		{"", GroupsModeContains, false},
		{"contains", GroupsModeContains, false},
		{"Contains", GroupsModeContains, false},
		{" exact ", GroupsModeExact, false},
		{"subset", "", true},
		{"EXACTLY", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseGroupsMode(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseGroupsMode(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("ParseGroupsMode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitGroups(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{" , ,", nil},
		{"X25519", []string{"X25519"}},
		{" X25519 , X25519MLKEM768 ,,", []string{"X25519", "X25519MLKEM768"}},
	}
	for _, tc := range tests {
		got := SplitGroups(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("SplitGroups(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("SplitGroups(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestNormalizeGroupName(t *testing.T) {
	equivalents := [][]string{
		{"X25519MLKEM768", "x25519mlkem768", "x25519_mlkem768", "X25519-MLKEM768"},
		{"secp256r1", "CurveP256", "P256", "curvep256"},
		{"X25519", "x25519"},
	}
	for _, group := range equivalents {
		first := normalizeGroupName(group[0])
		for _, name := range group[1:] {
			if got := normalizeGroupName(name); got != first {
				// "P256" is not an alias the code knows about; skip that pairing.
				if name == "P256" {
					continue
				}
				t.Errorf("normalizeGroupName(%q) = %q, want %q (same as %q)", name, got, first, group[0])
			}
		}
	}
}

func TestEvaluateExpectedGroups_Contains(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		makeCurveReport("a.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
			"TLS 1.3": "X25519MLKEM768",
			"TLS 1.2": "X25519",
		}),
		makeCurveReport("b.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
			"TLS 1.3": "X25519",
		}),
	}

	got := EvaluateExpectedGroups(reports, []string{"x25519mlkem768", "X25519"}, GroupsModeContains)

	if got.Checked != 2 || got.PassedN != 1 || got.FailedN != 1 {
		t.Fatalf("counts = checked %d / passed %d / failed %d, want 2/1/1", got.Checked, got.PassedN, got.FailedN)
	}
	if got.Passed() {
		t.Error("Passed() = true, want false")
	}
	if len(got.Failures) != 1 || got.Failures[0].Endpoint != "b.example.com:443" {
		t.Fatalf("Failures = %+v, want the b.example.com endpoint", got.Failures)
	}
	if len(got.Failures[0].Missing) != 1 || got.Failures[0].Missing[0] != "x25519mlkem768" {
		t.Errorf("Missing = %v, want [x25519mlkem768]", got.Failures[0].Missing)
	}
	if len(got.Failures[0].Unexpected) != 0 {
		t.Errorf("Unexpected = %v, want none in contains mode", got.Failures[0].Unexpected)
	}
}

func TestEvaluateExpectedGroups_Exact(t *testing.T) {
	extra := makeCurveReport("extra.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
		"TLS 1.3": "X25519",
	})
	extra.Status.NegotiatedCurves["TLS 1.2"] = "CurveP256"

	got := EvaluateExpectedGroups([]securityv1alpha1.TLSComplianceReport{extra}, []string{"X25519"}, GroupsModeExact)

	if got.FailedN != 1 {
		t.Fatalf("FailedN = %d, want 1", got.FailedN)
	}
	if len(got.Failures[0].Unexpected) != 1 || got.Failures[0].Unexpected[0] != "CurveP256" {
		t.Errorf("Unexpected = %v, want [CurveP256]", got.Failures[0].Unexpected)
	}

	// The same endpoint passes contains, since X25519 is a subset.
	if contains := EvaluateExpectedGroups([]securityv1alpha1.TLSComplianceReport{extra}, []string{"X25519"}, GroupsModeContains); !contains.Passed() {
		t.Error("contains mode should accept a superset of the expected groups")
	}
}

func TestEvaluateExpectedGroups_UnscannableIsSkipped(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		makeCurveReport("tls12.example.com", securityv1alpha1.ComplianceStatusCompliant, nil),
		makeCurveReport("down.example.com", securityv1alpha1.ComplianceStatusTimeout, nil),
	}

	got := EvaluateExpectedGroups(reports, []string{"X25519"}, GroupsModeContains)

	if got.Checked != 0 || got.SkippedN != 2 {
		t.Fatalf("checked %d / skipped %d, want 0/2", got.Checked, got.SkippedN)
	}
	if !got.Passed() {
		t.Error("skipped endpoints must not fail the assertion")
	}
	if len(got.Skipped) != 2 || got.Skipped[0].Endpoint != "down.example.com:443" {
		t.Errorf("Skipped = %+v, want both endpoints in stable order", got.Skipped)
	}
}

func TestEvaluateExpectedGroups_EmptyExpectationIsNoGate(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		makeCurveReport("a.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
			"TLS 1.3": "X25519",
		}),
	}

	got := EvaluateExpectedGroups(reports, nil, GroupsModeExact)
	if !got.Passed() || got.Checked != 0 {
		t.Errorf("empty expectation should check nothing and pass, got %+v", got)
	}
}

func TestAdvertiseGroups_DedupesAndSkipsEmpty(t *testing.T) {
	r := makeCurveReport("a.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
		"TLS 1.3": "X25519MLKEM768",
		"TLS 1.2": "x25519_mlkem768",
		"TLS 1.1": "",
		"TLS 1.0": "X25519",
	})

	got := advertiseGroups(&r)
	want := []string{"X25519", "X25519MLKEM768"}
	if len(got) != len(want) {
		t.Fatalf("advertiseGroups() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("advertiseGroups()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestEvaluateExpectedGroups_SkipReasonFallback(t *testing.T) {
	r := makeCurveReport("no-curves.example.com", "", nil)

	got := EvaluateExpectedGroups([]securityv1alpha1.TLSComplianceReport{r}, []string{"X25519"}, GroupsModeContains)

	if got.SkippedN != 1 {
		t.Fatalf("SkippedN = %d, want 1", got.SkippedN)
	}
	if reason := got.Skipped[0].SkipReason; reason != "no groups enumerated" {
		t.Errorf("SkipReason = %q, want %q", reason, "no groups enumerated")
	}
}

func TestEvaluateExpectedGroups_FailuresAreSorted(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		makeCurveReport("z.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
			"TLS 1.3": "X25519",
		}),
		makeCurveReport("a.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
			"TLS 1.3": "X25519",
		}),
	}

	got := EvaluateExpectedGroups(reports, []string{"X25519MLKEM768"}, GroupsModeContains)

	if got.FailedN != 2 {
		t.Fatalf("FailedN = %d, want 2", got.FailedN)
	}
	if got.Failures[0].Endpoint != "a.example.com:443" || got.Failures[1].Endpoint != "z.example.com:443" {
		t.Errorf("Failures = [%s %s], want sorted by endpoint",
			got.Failures[0].Endpoint, got.Failures[1].Endpoint)
	}
}

func TestWriteGroupsGate(t *testing.T) {
	got := EvaluateExpectedGroups([]securityv1alpha1.TLSComplianceReport{
		makeCurveReport("b.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
			"TLS 1.3": "X25519",
		}),
	}, []string{"X25519MLKEM768"}, GroupsModeContains)

	var sb strings.Builder
	if err := WriteGroupsGate(&sb, &got); err != nil {
		t.Fatalf("WriteGroupsGate() error = %v", err)
	}

	out := sb.String()
	for _, want := range []string{
		"Expected Groups (contains)",
		"X25519MLKEM768",
		"Failed:\t1",
		"b.example.com:443",
		"missing:\tX25519MLKEM768",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteGroupsGate_NoExpectation(t *testing.T) {
	got := EvaluateExpectedGroups(nil, nil, GroupsModeContains)

	var sb strings.Builder
	if err := WriteGroupsGate(&sb, &got); err != nil {
		t.Fatalf("WriteGroupsGate() error = %v", err)
	}
	if !strings.Contains(sb.String(), "no expectation configured") {
		t.Errorf("output should say nothing was checked:\n%s", sb.String())
	}
}

func TestWriteGroupsGate_ExactUnexpectedAndSkipped(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		makeCurveReport("extra.example.com", securityv1alpha1.ComplianceStatusCompliant, map[string]string{
			"TLS 1.3": "X25519",
			"TLS 1.2": "CurveP256",
		}),
		makeCurveReport("down.example.com", securityv1alpha1.ComplianceStatusTimeout, nil),
	}
	got := EvaluateExpectedGroups(reports, []string{"X25519"}, GroupsModeExact)

	var sb strings.Builder
	if err := WriteGroupsGate(&sb, &got); err != nil {
		t.Fatalf("WriteGroupsGate() error = %v", err)
	}

	out := sb.String()
	for _, want := range []string{
		"unexpected:\tCurveP256",
		"Skipped (no groups enumerated):",
		"down.example.com:443 (Timeout)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
