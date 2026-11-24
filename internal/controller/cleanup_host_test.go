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
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
)

// hostListenersFixture is a /proc/net/tcp table with one LISTEN socket on
// 8443 (0x20FB).
const hostListenersFixture = "  sl  local_address rem_address   st\n" +
	"   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 0 100 0 0 10 0\n"

// hostCleanupReport builds a host-mode report for the given listening port.
func hostCleanupReport(t *testing.T, name string, port int32) *securityv1alpha1.TLSComplianceReport {
	t.Helper()
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "127.0.0.1",
			Port:            port,
			SourceKind:      securityv1alpha1.SourceKindHost,
			SourceNamespace: "host",
			SourceName:      hostNodeName(),
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
		},
	}
}

// hostCleanupReconciler builds a fake-client reconciler holding the given
// reports, configured with the supplied host scan range and socket table
// directory.
func hostCleanupReconciler(t *testing.T, portRange *endpoint.PortRange, dir string, objs ...client.Object) *EndpointReconciler {
	t.Helper()
	scheme := newTestScheme()
	return &EndpointReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(objs...).
			WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
			Build(),
		Scheme:        scheme,
		HostScanPorts: portRange,
		ProcNetDir:    dir,
		Workers:       1,
	}
}

func assertReportDeleted(t *testing.T, r *EndpointReconciler, name string, wantDeleted bool) {
	t.Helper()
	var cr securityv1alpha1.TLSComplianceReport
	err := r.Get(context.Background(), client.ObjectKey{Name: name}, &cr)
	switch {
	case wantDeleted && !apierrors.IsNotFound(err):
		t.Errorf("expected %s deleted, got err=%v", name, err)
	case !wantDeleted && err != nil:
		t.Errorf("expected %s to remain, got %v", name, err)
	}
}

func TestCleanupOrphanedCRs_HostReportExemptFromNamespaceFilter(t *testing.T) {
	r := hostCleanupReconciler(t,
		&endpoint.PortRange{Start: 8000, End: 9000},
		writeProcNet(t, hostListenersFixture, ""),
		hostCleanupReport(t, "host-8443", 8443),
	)
	r.IncludeNamespaces = map[string]bool{"prod": true}

	if err := r.cleanupOrphanedCRs(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	assertReportDeleted(t, r, "host-8443", false)
}

func TestCleanupOrphanedCRs_HostReportKeptWhilePortListening(t *testing.T) {
	r := hostCleanupReconciler(t,
		&endpoint.PortRange{Start: 8000, End: 9000},
		writeProcNet(t, hostListenersFixture, ""),
		hostCleanupReport(t, "host-8443", 8443),
	)

	if err := r.cleanupOrphanedCRs(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	assertReportDeleted(t, r, "host-8443", false)
}

func TestCleanupOrphanedCRs_HostReportDeletedWhenScanDisabled(t *testing.T) {
	r := hostCleanupReconciler(t,
		nil,
		writeProcNet(t, hostListenersFixture, ""),
		hostCleanupReport(t, "host-8443", 8443),
	)

	if err := r.cleanupOrphanedCRs(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	assertReportDeleted(t, r, "host-8443", true)
}

func TestCleanupOrphanedCRs_HostReportDeletedWhenPortClosed(t *testing.T) {
	r := hostCleanupReconciler(t,
		&endpoint.PortRange{Start: 8000, End: 9000},
		writeProcNet(t, hostListenersFixture, ""),
		hostCleanupReport(t, "host-9443", 9443),
	)

	if err := r.cleanupOrphanedCRs(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	assertReportDeleted(t, r, "host-9443", true)
}

func TestCleanupOrphanedCRs_HostReportKeptWhenSocketTableUnreadable(t *testing.T) {
	// A missing tcp table must not delete reports this cycle.
	r := hostCleanupReconciler(t,
		&endpoint.PortRange{Start: 8000, End: 9000},
		t.TempDir(),
		hostCleanupReport(t, "host-8443", 8443),
	)

	if err := r.cleanupOrphanedCRs(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	assertReportDeleted(t, r, "host-8443", false)
}

func TestCleanupOrphanedCRs_HostReportDeletedWhenPortOutsideRange(t *testing.T) {
	// The socket is listening but falls outside --scan-host-ports, so the
	// operator will never refresh the report: treat it as orphaned.
	r := hostCleanupReconciler(t,
		&endpoint.PortRange{Start: 9000, End: 10000},
		writeProcNet(t, hostListenersFixture, ""),
		hostCleanupReport(t, "host-8443", 8443),
	)

	if err := r.cleanupOrphanedCRs(context.Background()); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	assertReportDeleted(t, r, "host-8443", true)
}
