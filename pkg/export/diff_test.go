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
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestDiffSnapshots_Identical(t *testing.T) {
	snap := []JSONReport{
		{Host: "app.example.com", Port: "443", Compliance: "Compliant", Grade: "A", TLS13: true, TLS12: true},
	}
	d := DiffSnapshots(snap, snap)
	if d.HasChanges() {
		t.Fatalf("expected no changes, got added=%d removed=%d changed=%d", len(d.Added), len(d.Removed), len(d.Changed))
	}
	if d.HasRegressions() {
		t.Fatal("expected no regressions")
	}
	if d.BeforeCount != 1 || d.AfterCount != 1 {
		t.Errorf("counts = %d → %d, want 1 → 1", d.BeforeCount, d.AfterCount)
	}
}

func TestDiffSnapshots_StatusChange(t *testing.T) {
	before := []JSONReport{
		{Host: "app.example.com", Port: "443", Compliance: "Compliant", Grade: "A"},
	}
	after := []JSONReport{
		{Host: "app.example.com", Port: "443", Compliance: "NonCompliant", Grade: "A"},
	}
	d := DiffSnapshots(before, after)
	if len(d.Changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(d.Changed))
	}
	if d.Changed[0].Endpoint != "app.example.com:443" {
		t.Errorf("endpoint = %q", d.Changed[0].Endpoint)
	}
	if len(d.Changed[0].Fields) != 1 || d.Changed[0].Fields[0].Field != "compliance" {
		t.Fatalf("fields = %+v, want compliance", d.Changed[0].Fields)
	}
	if !d.Changed[0].Fields[0].Regression {
		t.Error("expected compliance change to be a regression")
	}
	if d.Regressions != 1 {
		t.Errorf("regressions = %d, want 1", d.Regressions)
	}
}

func TestDiffSnapshots_AddedRemoved(t *testing.T) {
	before := []JSONReport{
		{Host: "old.example.com", Port: "443", Compliance: "Compliant", Grade: "A"},
		{Host: "keep.example.com", Port: "443", Compliance: "Compliant", Grade: "A"},
	}
	after := []JSONReport{
		{Host: "keep.example.com", Port: "443", Compliance: "Compliant", Grade: "A"},
		{Host: "new.example.com", Port: "443", Compliance: "Compliant", Grade: "A"},
		{Host: "bad.example.com", Port: "443", Compliance: "NoTLS"},
	}
	d := DiffSnapshots(before, after)
	if got := hostsFromJSON(d.Added); !slices.Equal(got, []string{"bad.example.com:443", "new.example.com:443"}) {
		t.Errorf("added = %v", got)
	}
	if got := hostsFromJSON(d.Removed); !slices.Equal(got, []string{"old.example.com:443"}) {
		t.Errorf("removed = %v", got)
	}
	if len(d.Changed) != 0 {
		t.Errorf("changed = %+v, want none", d.Changed)
	}
	if d.Regressions != 1 {
		t.Errorf("regressions = %d, want 1 (added NoTLS)", d.Regressions)
	}
}

func TestDiffSnapshots_GradeAndLegacyTLS(t *testing.T) {
	before := JSONReport{Host: "app.example.com", Port: "443", Compliance: "Compliant", Grade: "A", TLS13: true, TLS12: true}
	after := before
	after.Grade = "C"
	after.TLS10 = true
	d := DiffSnapshots([]JSONReport{before}, []JSONReport{after})
	if d.Regressions != 1 {
		t.Fatalf("regressions = %d, want 1", d.Regressions)
	}
	got := fieldNames(d.Changed[0].Fields)
	if !containsAll(got, []string{"grade", "tls10"}) {
		t.Errorf("fields = %v, want grade and tls10", got)
	}
	for _, f := range d.Changed[0].Fields {
		if (f.Field == "grade" || f.Field == "tls10") && !f.Regression {
			t.Errorf("%s should be a regression", f.Field)
		}
	}
}

func TestDiffSnapshots_ImprovementIsNotRegression(t *testing.T) {
	before := JSONReport{Host: "app.example.com", Port: "443", Compliance: "NonCompliant", Grade: "F", TLS10: true, PQCReadiness: "NoPQC"}
	after := JSONReport{Host: "app.example.com", Port: "443", Compliance: "Compliant", Grade: "A", TLS13: true, TLS12: true, PQCReadiness: "PQCReady"}
	d := DiffSnapshots([]JSONReport{before}, []JSONReport{after})
	if !d.HasChanges() {
		t.Fatal("expected changes")
	}
	if d.HasRegressions() {
		t.Fatalf("improvements should not count as regressions: %+v", d.Changed)
	}
}

func TestDiffSnapshots_TLS13LostAndPQCDrop(t *testing.T) {
	before := JSONReport{
		Host: "app.example.com", Port: "443", Compliance: "Compliant", Grade: "A",
		TLS13: true, TLS12: true, PQCReadiness: "PQCReady", MLKEMSupported: true, QuantumReady: true, ForwardSecrecy: true,
	}
	after := before
	after.TLS13 = false
	after.PQCReadiness = "LegacyTLS"
	after.MLKEMSupported = false
	d := DiffSnapshots([]JSONReport{before}, []JSONReport{after})
	if d.Regressions != 1 {
		t.Errorf("regressions = %d, want 1", d.Regressions)
	}
	got := fieldNames(d.Changed[0].Fields)
	if !containsAll(got, []string{"tls13", "pqcReadiness", "mlkemSupported"}) {
		t.Errorf("fields = %v", got)
	}
}

func TestDiffSnapshots_CertExpiryIsNotRegression(t *testing.T) {
	before := JSONReport{Host: "app.example.com", Port: "443", Compliance: "Compliant", CertExpiry: "2027-01-01", CertIssuer: "Old CA"}
	after := JSONReport{Host: "app.example.com", Port: "443", Compliance: "Compliant", CertExpiry: "2026-06-15", CertIssuer: "New CA"}
	d := DiffSnapshots([]JSONReport{before}, []JSONReport{after})
	if len(d.Changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(d.Changed))
	}
	if d.HasRegressions() {
		t.Fatal("cert rotation should not count as a regression")
	}
}

func TestWriteDiff_NoDifferences(t *testing.T) {
	d := DiffSnapshots(nil, nil)
	var buf bytes.Buffer
	if err := WriteDiff(&buf, &d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "TLS compliance diff: 0 → 0 endpoints") {
		t.Errorf("output = %q", out)
	}
	if !strings.Contains(out, "No differences.") {
		t.Errorf("output = %q", out)
	}
}

func TestWriteDiff_ChangesAndRegressions(t *testing.T) {
	before := []JSONReport{
		{Host: "app.example.com", Port: "443", Compliance: "Compliant", Grade: "A", PQCReadiness: "PQCReady"},
		{Host: "gone.example.com", Port: "443", Compliance: "Compliant", Grade: "A", PQCReadiness: "PQCReady"},
	}
	after := []JSONReport{
		{Host: "app.example.com", Port: "443", Compliance: "NonCompliant", Grade: "C", PQCReadiness: "LegacyTLS"},
		{Host: "new.example.com", Port: "443", Compliance: "Compliant", Grade: "A", PQCReadiness: "PQCReady"},
	}
	d := DiffSnapshots(before, after)
	var buf bytes.Buffer
	if err := WriteDiff(&buf, &d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Added (1):",
		"new.example.com:443",
		"Removed (1):",
		"gone.example.com:443",
		"Changed (1):",
		"compliance: Compliant → NonCompliant  (regression)",
		"grade: A → C  (regression)",
		"1 regression",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestWriteDiffJSON(t *testing.T) {
	before := []JSONReport{{Host: "app.example.com", Port: "443", Compliance: "Compliant"}}
	after := []JSONReport{{Host: "app.example.com", Port: "443", Compliance: "Warning"}}
	d := DiffSnapshots(before, after)
	var buf bytes.Buffer
	if err := WriteDiffJSON(&buf, &d); err != nil {
		t.Fatal(err)
	}
	var parsed SnapshotDiff
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if parsed.Regressions != 1 {
		t.Errorf("regressions = %d, want 1", parsed.Regressions)
	}
	if len(parsed.Changed) != 1 {
		t.Fatalf("changed = %d", len(parsed.Changed))
	}
}

func TestLoadSnapshot_JSONAndYAMLRoundTrip(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "app-443-abcd1234"},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host: "app.example.com",
				Port: 443,
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus:   securityv1alpha1.ComplianceStatusCompliant,
				OverallCipherGrade: "A",
			},
		},
	}

	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, reports); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSnapshot(jsonBuf.Bytes())
	if err != nil {
		t.Fatalf("LoadSnapshot JSON: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Host != "app.example.com" || loaded[0].Port != "443" {
		t.Fatalf("JSON snapshot = %+v", loaded)
	}

	var yamlBuf bytes.Buffer
	if err := WriteYAML(&yamlBuf, reports); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadSnapshot(yamlBuf.Bytes())
	if err != nil {
		t.Fatalf("LoadSnapshot YAML: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Host != "app.example.com" || loaded[0].Compliance != "Compliant" {
		t.Fatalf("YAML snapshot = %+v", loaded)
	}
}

func TestLoadSnapshot_Errors(t *testing.T) {
	if _, err := LoadSnapshot(nil); err == nil || !strings.Contains(err.Error(), "empty snapshot") {
		t.Errorf("nil: %v", err)
	}
	if _, err := LoadSnapshot([]byte("   ")); err == nil || !strings.Contains(err.Error(), "empty snapshot") {
		t.Errorf("whitespace: %v", err)
	}
	if _, err := LoadSnapshot([]byte("{not-json")); err == nil || !strings.Contains(err.Error(), "parsing JSON snapshot") {
		t.Errorf("invalid JSON: %v", err)
	}
	if _, err := LoadSnapshot([]byte(":\nbad")); err == nil || !strings.Contains(err.Error(), "parsing YAML snapshot") {
		t.Errorf("invalid YAML: %v", err)
	}
}

func hostsFromJSON(reports []JSONReport) []string {
	out := make([]string, len(reports))
	for i := range reports {
		out[i] = reports[i].EndpointKey()
	}
	return out
}

func TestDiffSnapshots_InfraStatusIsNotRegression(t *testing.T) {
	before := []JSONReport{{Host: "app.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusTimeout)}}
	after := []JSONReport{{Host: "app.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusWarning)}}
	d := DiffSnapshots(before, after)
	if len(d.Changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(d.Changed))
	}
	if d.HasRegressions() {
		t.Fatal("Timeout → Warning should not count as a regression")
	}
}

func TestDiffSnapshots_EmptyGradeIsNotRegression(t *testing.T) {
	before := JSONReport{Host: "app.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusCompliant), Grade: "A"}
	after := before
	after.Grade = ""
	d := DiffSnapshots([]JSONReport{before}, []JSONReport{after})
	if !d.HasChanges() {
		t.Fatal("expected grade change")
	}
	if d.HasRegressions() {
		t.Fatal("empty grade should not count as a regression")
	}
}

func TestWriteDiff_ImprovementsAndPluralRegressions(t *testing.T) {
	improvedBefore := []JSONReport{{Host: "ok.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusNonCompliant), Grade: "F"}}
	improvedAfter := []JSONReport{{Host: "ok.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusCompliant), Grade: "A"}}
	d := DiffSnapshots(improvedBefore, improvedAfter)
	var buf bytes.Buffer
	if err := WriteDiff(&buf, &d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No regressions.") {
		t.Errorf("output = %q", buf.String())
	}

	regressed := DiffSnapshots(
		[]JSONReport{
			{Host: "a.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusCompliant)},
			{Host: "b.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusCompliant)},
		},
		[]JSONReport{
			{Host: "a.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusNonCompliant)},
			{Host: "b.example.com", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusNoTLS)},
		},
	)
	buf.Reset()
	if err := WriteDiff(&buf, &regressed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "2 regressions") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestDiffSnapshots_IPv6Key(t *testing.T) {
	before := []JSONReport{{Host: "::1", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusCompliant)}}
	after := []JSONReport{{Host: "::1", Port: "443", Compliance: string(securityv1alpha1.ComplianceStatusNonCompliant)}}
	d := DiffSnapshots(before, after)
	if len(d.Changed) != 1 || d.Changed[0].Endpoint != "[::1]:443" {
		t.Fatalf("changed = %+v", d.Changed)
	}
}

func fieldNames(fields []FieldChange) []string {
	out := make([]string, len(fields))
	for i := range fields {
		out[i] = fields[i].Field
	}
	return out
}

func containsAll(got, want []string) bool {
	set := make(map[string]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
