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

package main

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func useFakeCommandClient(t *testing.T, objects ...client.Object) client.WithWatch {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	original := clientBuilder
	clientBuilder = func() (client.WithWatch, error) { return c, nil }
	t.Cleanup(func() { clientBuilder = original })
	return c
}

func commandReport() *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "report-1"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "example.com", Port: 443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: "default", SourceName: "example",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
		},
	}
}

func TestRunGet_ListsAndGetsReport(t *testing.T) {
	useFakeCommandClient(t, commandReport())
	filterOpts = export.FilterOptions{}
	sortBy = ""
	t.Cleanup(func() { outputFormat = ""; filterOpts = export.FilterOptions{}; sortBy = "" })

	cmd := newGetCmd()
	cmd.SetContext(context.Background())
	outputFormat = "json"
	output := captureStdout(t, func() {
		if err := runGet(cmd, nil, false); err != nil {
			t.Fatalf("runGet() error = %v", err)
		}
	})
	if !strings.Contains(output, `"crName": "report-1"`) {
		t.Errorf("list output = %q, want report-1", output)
	}

	output = captureStdout(t, func() {
		if err := runGet(cmd, []string{"report-1"}, false); err != nil {
			t.Fatalf("runGet(name) error = %v", err)
		}
	})
	if !strings.Contains(output, `"crName": "report-1"`) {
		t.Errorf("named output = %q, want report-1", output)
	}
	if err := runGet(cmd, []string{"missing"}, false); err == nil || !strings.Contains(err.Error(), `report "missing" not found`) {
		t.Fatalf("runGet(missing) error = %v", err)
	}
}

func TestRunGetWatch_CancelledContext(t *testing.T) {
	useFakeCommandClient(t, commandReport())
	cmd := newGetCmd()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd.SetContext(ctx)
	outputFormat = "table"
	t.Cleanup(func() { outputFormat = "" })

	if err := runGetWatch(cmd, nil); err != nil {
		t.Fatalf("runGetWatch() error = %v", err)
	}
}

func TestRunDescribe_FoundAndMissing(t *testing.T) {
	useFakeCommandClient(t, commandReport())
	cmd := newDescribeCmd()
	cmd.SetContext(context.Background())

	output := captureStdout(t, func() {
		if err := runDescribe(cmd, []string{"report-1"}); err != nil {
			t.Fatalf("runDescribe() error = %v", err)
		}
	})
	if !strings.Contains(output, "Name:         report-1") {
		t.Errorf("describe output = %q, want report name", output)
	}
	if err := runDescribe(cmd, []string{"missing"}); err == nil || !strings.Contains(err.Error(), `report "missing" not found`) {
		t.Fatalf("runDescribe(missing) error = %v", err)
	}
}

func TestRunSummary_WritesSummaryAndChecksStatus(t *testing.T) {
	report := commandReport()
	report.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusNonCompliant
	useFakeCommandClient(t, report)
	filterOpts = export.FilterOptions{}
	sortBy = ""
	failOnNonCompliant = true
	t.Cleanup(func() { filterOpts = export.FilterOptions{}; sortBy = ""; failOnNonCompliant = false })

	cmd := newSummaryCmd()
	cmd.SetContext(context.Background())
	output := captureStdout(t, func() {
		if err := runSummary(cmd, nil); err == nil {
			t.Fatal("runSummary() returned nil, want non-compliant exit error")
		}
	})
	if !strings.Contains(output, "Total Endpoints") {
		t.Errorf("summary output = %q, want summary header", output)
	}
}

func TestRunRescan_TriggersAnnotation(t *testing.T) {
	report := commandReport()
	c := useFakeCommandClient(t, report)
	cmd := newRescanCmd()
	cmd.SetContext(context.Background())

	stderr := captureStderr(t, func() {
		if err := runRescan(context.Background(), "report-1", false, 0); err != nil {
			t.Fatalf("runRescan() error = %v", err)
		}
	})
	if !strings.Contains(stderr, "Rescan triggered for report-1") {
		t.Errorf("stderr = %q, want trigger message", stderr)
	}
	var got securityv1alpha1.TLSComplianceReport
	if err := c.Get(context.Background(), client.ObjectKey{Name: "report-1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations[securityv1alpha1.RescanAnnotation] == "" {
		t.Error("rescan annotation was not persisted")
	}
	if err := runRescan(cmd.Context(), "missing", false, 0); err == nil || !strings.Contains(err.Error(), `report "missing" not found`) {
		t.Fatalf("runRescan(missing) error = %v", err)
	}
}

func TestRunRescanAll_TriggersMatchingReports(t *testing.T) {
	report := commandReport()
	c := useFakeCommandClient(t, report)
	filterOpts = export.FilterOptions{}
	t.Cleanup(func() { filterOpts = export.FilterOptions{} })

	if err := runRescanAll(context.Background(), false, 0); err != nil {
		t.Fatalf("runRescanAll() error = %v", err)
	}
	var got securityv1alpha1.TLSComplianceReport
	if err := c.Get(context.Background(), client.ObjectKey{Name: "report-1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations[securityv1alpha1.RescanAnnotation] == "" {
		t.Error("rescan annotation was not persisted")
	}
}

func TestRunTargetCommands(t *testing.T) {
	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "target-1"},
		Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "example.com", Port: int32Pointer(443)},
	}
	c := useFakeCommandClient(t, target)
	filterOpts = export.FilterOptions{}
	sortBy = ""
	t.Cleanup(func() { targetOutputFormat = ""; filterOpts = export.FilterOptions{}; sortBy = "" })

	listCmd := newTargetListCmd()
	listCmd.SetContext(context.Background())
	targetOutputFormat = "json"
	listOutput := captureStdout(t, func() {
		if err := runTargetList(listCmd, nil); err != nil {
			t.Fatalf("runTargetList() error = %v", err)
		}
	})
	if !strings.Contains(listOutput, `"name": "target-1"`) {
		t.Errorf("target list output = %q, want target-1", listOutput)
	}

	getCmd := newTargetGetCmd()
	getCmd.SetContext(context.Background())
	targetOutputFormat = "json"
	getOutput := captureStdout(t, func() {
		if err := runTargetGet(getCmd, []string{"target-1"}); err != nil {
			t.Fatalf("runTargetGet() error = %v", err)
		}
	})
	if !strings.Contains(getOutput, `"name": "target-1"`) {
		t.Errorf("target get output = %q, want target-1", getOutput)
	}

	describeCmd := newTargetDescribeCmd()
	describeCmd.SetContext(context.Background())
	describeOutput := captureStdout(t, func() {
		if err := runTargetDescribe(describeCmd, []string{"target-1"}); err != nil {
			t.Fatalf("runTargetDescribe() error = %v", err)
		}
	})
	if !strings.Contains(describeOutput, "Name:         target-1") {
		t.Errorf("target describe output = %q, want target name", describeOutput)
	}

	createCmd := newTargetCreateCmd()
	createCmd.SetContext(context.Background())
	if err := runTargetCreate(createCmd, []string{"new.example.com", "8443"}, false, 0); err != nil {
		t.Fatalf("runTargetCreate() error = %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "new-example-com-8443"}, &securityv1alpha1.TLSComplianceTarget{}); err != nil {
		t.Fatalf("created target was not persisted: %v", err)
	}

	if err := runTargetUpdate(context.Background(), "target-1", "updated.example.com", 8443, true, true); err != nil {
		t.Fatalf("runTargetUpdate() error = %v", err)
	}
	if err := runTargetDelete(context.Background(), []string{"target-1"}, false); err != nil {
		t.Fatalf("runTargetDelete() error = %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "target-1"}, &securityv1alpha1.TLSComplianceTarget{}); err == nil {
		t.Error("target still exists after delete")
	}
}

func TestRunTargetDeleteAll(t *testing.T) {
	targets := sampleTargets()
	c := useFakeCommandClient(t, &targets[0], &targets[1], &targets[2])
	if err := runTargetDelete(context.Background(), nil, true); err != nil {
		t.Fatalf("runTargetDelete(--all) error = %v", err)
	}
	var remaining securityv1alpha1.TLSComplianceTargetList
	if err := c.List(context.Background(), &remaining); err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 0 {
		t.Errorf("remaining targets = %d, want 0", len(remaining.Items))
	}
}
