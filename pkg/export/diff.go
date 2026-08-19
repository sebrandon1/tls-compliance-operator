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
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// SnapshotDiff is the result of comparing two JSON/YAML export snapshots.
type SnapshotDiff struct {
	BeforeCount int               `json:"beforeCount"`
	AfterCount  int               `json:"afterCount"`
	Added       []JSONReport      `json:"added"`
	Removed     []JSONReport      `json:"removed"`
	Changed     []ChangedEndpoint `json:"changed"`
	Regressions int               `json:"regressions"`
}

// ChangedEndpoint is a host:port present in both snapshots with field deltas.
type ChangedEndpoint struct {
	Endpoint string        `json:"endpoint"`
	Fields   []FieldChange `json:"fields"`
}

// FieldChange is a single snapshot field that differed.
type FieldChange struct {
	Field      string `json:"field"`
	From       string `json:"from"`
	To         string `json:"to"`
	Regression bool   `json:"regression"`
}

var pqcRank = func() map[string]int {
	m := make(map[string]int, len(knownPQCReadiness))
	for i, r := range knownPQCReadiness {
		m[string(r)] = i
	}
	return m
}()

// snapshotComplianceRank orders comparable scan results from best to worst.
// Infrastructure statuses (Timeout, Unreachable, Pending, ...) are omitted so
// they never count as a compliance regression.
var snapshotComplianceRank = map[securityv1alpha1.ComplianceStatus]int{
	securityv1alpha1.ComplianceStatusCompliant:         0,
	securityv1alpha1.ComplianceStatusWarning:           1,
	securityv1alpha1.ComplianceStatusMutualTLSRequired: 1,
	securityv1alpha1.ComplianceStatusNonCompliant:      2,
	securityv1alpha1.ComplianceStatusNoTLS:             2,
	securityv1alpha1.ComplianceStatusPlaintextHTTP:     2,
}

// LoadSnapshot parses a JSON or YAML export produced by WriteJSON / WriteYAML.
func LoadSnapshot(data []byte) ([]JSONReport, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty snapshot")
	}

	var reports []JSONReport
	if data[0] == '[' || data[0] == '{' {
		if err := json.Unmarshal(data, &reports); err != nil {
			return nil, fmt.Errorf("parsing JSON snapshot: %w", err)
		}
		return reports, nil
	}

	if err := yaml.Unmarshal(data, &reports); err != nil {
		return nil, fmt.Errorf("parsing YAML snapshot: %w", err)
	}
	return reports, nil
}

// DiffSnapshots compares two flattened report lists, keyed by host:port.
func DiffSnapshots(before, after []JSONReport) SnapshotDiff {
	beforeMap := indexByEndpoint(before)
	afterMap := indexByEndpoint(after)

	d := SnapshotDiff{
		BeforeCount: len(before),
		AfterCount:  len(after),
		Added:       make([]JSONReport, 0),
		Removed:     make([]JSONReport, 0),
		Changed:     make([]ChangedEndpoint, 0),
	}

	for key := range afterMap {
		beforeReport, ok := beforeMap[key]
		if !ok {
			d.Added = append(d.Added, afterMap[key])
			continue
		}
		afterReport := afterMap[key]
		fields := diffFields(&beforeReport, &afterReport)
		if len(fields) > 0 {
			d.Changed = append(d.Changed, ChangedEndpoint{Endpoint: key, Fields: fields})
		}
	}
	for key := range beforeMap {
		if _, ok := afterMap[key]; !ok {
			d.Removed = append(d.Removed, beforeMap[key])
		}
	}

	sort.Slice(d.Added, func(i, j int) bool {
		return d.Added[i].EndpointKey() < d.Added[j].EndpointKey()
	})
	sort.Slice(d.Removed, func(i, j int) bool {
		return d.Removed[i].EndpointKey() < d.Removed[j].EndpointKey()
	})
	slices.SortFunc(d.Changed, func(a, b ChangedEndpoint) int {
		return cmp.Compare(a.Endpoint, b.Endpoint)
	})

	d.Regressions = countRegressions(&d)
	return d
}

// HasChanges reports whether any endpoint was added, removed, or changed.
func (d *SnapshotDiff) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0
}

// HasRegressions reports whether any change is a compliance regression.
func (d *SnapshotDiff) HasRegressions() bool {
	return d.Regressions > 0
}

// WriteDiff writes a human-readable snapshot comparison to w.
func WriteDiff(w io.Writer, d *SnapshotDiff) error {
	ew := &errWriter{w: w}
	ew.printf("TLS compliance diff: %d → %d endpoints\n", d.BeforeCount, d.AfterCount)
	if !d.HasChanges() {
		ew.printf("No differences.\n")
		return ew.err
	}

	writeDiffGroup(ew, "Added", d.Added, true)
	writeDiffGroup(ew, "Removed", d.Removed, false)
	if len(d.Changed) > 0 {
		ew.printf("\nChanged (%d):\n", len(d.Changed))
		for i := range d.Changed {
			ew.printf("  %s\n", d.Changed[i].Endpoint)
			for _, f := range d.Changed[i].Fields {
				suffix := ""
				if f.Regression {
					suffix = "  (regression)"
				}
				ew.printf("    %s: %s → %s%s\n", f.Field, emptyDash(f.From), emptyDash(f.To), suffix)
			}
		}
	}

	if d.Regressions == 0 {
		ew.printf("\nNo regressions.\n")
		return ew.err
	}
	label := "regression"
	if d.Regressions != 1 {
		label = "regressions"
	}
	ew.printf("\n%d %s\n", d.Regressions, label)
	return ew.err
}

// WriteDiffJSON writes SnapshotDiff as pretty-printed JSON.
func WriteDiffJSON(w io.Writer, d *SnapshotDiff) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return fmt.Errorf("encoding diff JSON: %w", err)
	}
	return nil
}

func writeDiffGroup(ew *errWriter, title string, reports []JSONReport, markRegression bool) {
	if len(reports) == 0 {
		return
	}
	ew.printf("\n%s (%d):\n", title, len(reports))
	for i := range reports {
		r := &reports[i]
		marker := ""
		if markRegression && isNonCompliantSnapshot(r.Compliance) {
			marker = "  [regression]"
		}
		ew.printf("  %s  %s  grade=%s  pqc=%s%s\n",
			r.EndpointKey(), r.Compliance, r.Grade, r.PQCReadiness, marker)
	}
}

func indexByEndpoint(reports []JSONReport) map[string]JSONReport {
	// Last write wins for duplicate host:port keys. Snapshots are compared by
	// endpoint identity (host:port), not CR name.
	out := make(map[string]JSONReport, len(reports))
	for i := range reports {
		out[reports[i].EndpointKey()] = reports[i]
	}
	return out
}

func diffFields(before, after *JSONReport) []FieldChange {
	var fields []FieldChange
	addChange := func(name, from, to string, regression bool) {
		if from != to {
			fields = append(fields, FieldChange{Field: name, From: from, To: to, Regression: regression})
		}
	}

	addChange("compliance", before.Compliance, after.Compliance, isComplianceRegression(before.Compliance, after.Compliance))
	addChange("grade", before.Grade, after.Grade, isGradeRegression(before.Grade, after.Grade))
	addChange("tls13", boolString(before.TLS13), boolString(after.TLS13), before.TLS13 && !after.TLS13)
	addChange("tls12", boolString(before.TLS12), boolString(after.TLS12), false)
	addChange("tls11", boolString(before.TLS11), boolString(after.TLS11), !before.TLS11 && after.TLS11)
	addChange("tls10", boolString(before.TLS10), boolString(after.TLS10), !before.TLS10 && after.TLS10)
	addChange("ssl30", boolString(before.SSL30), boolString(after.SSL30), !before.SSL30 && after.SSL30)
	addChange("pqcReadiness", before.PQCReadiness, after.PQCReadiness, isPQCRegression(before.PQCReadiness, after.PQCReadiness))
	addChange("mlkemSupported", boolString(before.MLKEMSupported), boolString(after.MLKEMSupported), before.MLKEMSupported && !after.MLKEMSupported)
	addChange("forwardSecrecy", boolString(before.ForwardSecrecy), boolString(after.ForwardSecrecy), before.ForwardSecrecy && !after.ForwardSecrecy)
	addChange("certExpiry", before.CertExpiry, after.CertExpiry, false)
	addChange("certIssuer", before.CertIssuer, after.CertIssuer, false)

	return fields
}

func countRegressions(d *SnapshotDiff) int {
	n := 0
	for i := range d.Added {
		if isNonCompliantSnapshot(d.Added[i].Compliance) {
			n++
		}
	}
	for i := range d.Changed {
		for _, f := range d.Changed[i].Fields {
			if f.Regression {
				n++
				break
			}
		}
	}
	return n
}

func isNonCompliantSnapshot(status string) bool {
	return NonCompliantStatuses[securityv1alpha1.ComplianceStatus(status)]
}

func isComplianceRegression(from, to string) bool {
	fr, fok := snapshotComplianceRank[securityv1alpha1.ComplianceStatus(from)]
	tr, tok := snapshotComplianceRank[securityv1alpha1.ComplianceStatus(to)]
	if !fok || !tok {
		return false
	}
	return tr > fr
}

func isGradeRegression(from, to string) bool {
	return isRankRegression(strings.ToUpper(from), strings.ToUpper(to), gradeRank)
}

func isPQCRegression(from, to string) bool {
	return isRankRegression(from, to, pqcRank)
}

func isRankRegression(from, to string, rank map[string]int) bool {
	if from == "" || to == "" {
		return false
	}
	fr, fok := rank[from]
	tr, tok := rank[to]
	if !fok || !tok {
		return false
	}
	return tr > fr
}

func boolString(v bool) string {
	return strconv.FormatBool(v)
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
