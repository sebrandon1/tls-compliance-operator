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

package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
)

// writeProcNet writes tcp and tcp6 fixtures into a temp directory.
func writeProcNet(t *testing.T, tcp, tcp6 string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(tcp), 0o600); err != nil {
		t.Fatalf("write tcp: %v", err)
	}
	if tcp6 != "" {
		if err := os.WriteFile(filepath.Join(dir, "tcp6"), []byte(tcp6), 0o600); err != nil {
			t.Fatalf("write tcp6: %v", err)
		}
	}
	return dir
}

func TestReadHostListeners_DedupesV4AndV6(t *testing.T) {
	tcp := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 0 100 0 0 10 0\n"
	tcp6 := "  sl  local_address rem_address   st\n" +
		"   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 0 100 0 0 10 0\n" +
		"   1: 00000000000000000000000000000000:24E3 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2 1 0 0 100 0 0 10 0\n"

	ports, err := readHostListeners(writeProcNet(t, tcp, tcp6))
	if err != nil {
		t.Fatalf("readHostListeners() error = %v", err)
	}
	if len(ports) != 2 || ports[0] != 8443 || ports[1] != 9443 {
		t.Errorf("ports = %v, want [8443 9443] (v4 deduped with v6)", ports)
	}
}

func TestReadHostListeners_MissingTable(t *testing.T) {
	if _, err := readHostListeners(t.TempDir()); err == nil {
		t.Fatal("readHostListeners() error = nil, want an error when tcp is missing")
	}
}

func TestScanHostEndpoints_FiltersRange(t *testing.T) {
	tcp := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 0 100 0 0 10 0\n" +
		"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2 1 0 0 100 0 0 10 0\n"
	dir := writeProcNet(t, tcp, "")

	portRange := endpoint.PortRange{Start: 8000, End: 9000}
	r := hostScanReconciler(t, &portRange, dir)

	if err := r.scanHostEndpoints(context.Background()); err != nil {
		t.Fatalf("scanHostEndpoints() error = %v", err)
	}

	reports := listReports(t, r)
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want one in-range endpoint", len(reports))
	}
	report := reports[0]
	if report.Spec.SourceKind != securityv1alpha1.SourceKindHost {
		t.Errorf("SourceKind = %q, want Host", report.Spec.SourceKind)
	}
	if report.Spec.Host != "127.0.0.1" || report.Spec.Port != 8443 {
		t.Errorf("endpoint = %s:%d, want 127.0.0.1:8443", report.Spec.Host, report.Spec.Port)
	}
}

func TestScanHostEndpoints_DisabledIsNoop(t *testing.T) {
	r := hostScanReconciler(t, nil, t.TempDir())
	if err := r.scanHostEndpoints(context.Background()); err != nil {
		t.Fatalf("scanHostEndpoints() error = %v", err)
	}
	if reports := listReports(t, r); len(reports) != 0 {
		t.Errorf("reports = %d, want none when disabled", len(reports))
	}
}

// hostScanReconciler builds a reconciler backed by a fake client.
func hostScanReconciler(t *testing.T, portRange *endpoint.PortRange, dir string) *EndpointReconciler {
	t.Helper()
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).Build()
	return &EndpointReconciler{
		Client:        c,
		Scheme:        scheme,
		HostScanPorts: portRange,
		ProcNetDir:    dir,
		Workers:       1,
		ManagerCtx:    context.Background(),
	}
}

// listReports returns the reports in the fake client.
func listReports(t *testing.T, r *EndpointReconciler) []securityv1alpha1.TLSComplianceReport {
	t.Helper()
	var list securityv1alpha1.TLSComplianceReportList
	if err := r.List(context.Background(), &list); err != nil {
		t.Fatalf("list reports: %v", err)
	}
	return list.Items
}
