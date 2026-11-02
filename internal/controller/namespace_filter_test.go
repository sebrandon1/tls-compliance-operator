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
	"slices"
	"sort"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

func filterTestReport(name string, kind securityv1alpha1.SourceKind, namespace, sourceName string) *securityv1alpha1.TLSComplianceReport {
	now := metav1.Now()
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            name + ".example.com",
			Port:            443,
			SourceKind:      kind,
			SourceNamespace: namespace,
			SourceName:      sourceName,
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
		},
	}
}

// newFilterTestReconciler builds a reconciler holding one Service report in
// "keep", one in "drop", and one TLSComplianceTarget report, plus the source
// objects for all three so cleanup does not treat any as orphaned.
func newFilterTestReconciler(t *testing.T, checker tlscheck.Checker) *EndpointReconciler {
	t.Helper()
	scheme := newTestScheme()
	objs := []client.Object{
		filterTestReport("keep-svc", securityv1alpha1.SourceKindService, "keep", "svc"),
		filterTestReport("drop-svc", securityv1alpha1.SourceKindService, "drop", "svc"),
		filterTestReport("target", securityv1alpha1.SourceKindTarget, "cluster-scoped", "tgt"),
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "keep"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "drop"}},
		&securityv1alpha1.TLSComplianceTarget{ObjectMeta: metav1.ObjectMeta{Name: "tgt"}},
	}
	return &EndpointReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(objs...).
			WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
			Build(),
		Scheme:     scheme,
		TLSChecker: checker,
		Workers:    1,
	}
}

// filterModes are equivalent filters that keep namespace "keep" and drop "drop".
var filterModes = []struct {
	name    string
	include map[string]bool
	exclude map[string]bool
}{
	{name: "include", include: map[string]bool{"keep": true}},
	{name: "exclude", exclude: map[string]bool{"drop": true}},
}

func TestIsReportFiltered(t *testing.T) {
	tests := []struct {
		name    string
		include map[string]bool
		exclude map[string]bool
		kind    securityv1alpha1.SourceKind
		ns      string
		want    bool
	}{
		{name: "no filter", kind: securityv1alpha1.SourceKindService, ns: "a", want: false},
		{name: "included", include: map[string]bool{"a": true}, kind: securityv1alpha1.SourceKindService, ns: "a", want: false},
		{name: "not included", include: map[string]bool{"a": true}, kind: securityv1alpha1.SourceKindPod, ns: "b", want: true},
		{name: "excluded", exclude: map[string]bool{"b": true}, kind: securityv1alpha1.SourceKindIngress, ns: "b", want: true},
		{name: "target with include", include: map[string]bool{"a": true}, kind: securityv1alpha1.SourceKindTarget, ns: "cluster-scoped", want: false},
		{name: "target with exclude", exclude: map[string]bool{"cluster-scoped": true}, kind: securityv1alpha1.SourceKindTarget, ns: "cluster-scoped", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &EndpointReconciler{IncludeNamespaces: tt.include, ExcludeNamespaces: tt.exclude}
			if got := r.isReportFiltered(tt.kind, tt.ns); got != tt.want {
				t.Errorf("isReportFiltered(%s, %s) = %v, want %v", tt.kind, tt.ns, got, tt.want)
			}
		})
	}
}

func TestScanAllEndpoints_SkipsFilteredNamespaces(t *testing.T) {
	for _, tt := range filterModes {
		t.Run(tt.name, func(t *testing.T) {
			var probed []string
			checker := &OrderTrackingChecker{
				result: &tlscheck.TLSCheckResult{SupportsTLS12: true, SupportsTLS13: true, CipherSuites: map[string][]string{}},
				order:  &probed,
				mu:     &sync.Mutex{},
			}
			r := newFilterTestReconciler(t, checker)
			r.IncludeNamespaces = tt.include
			r.ExcludeNamespaces = tt.exclude

			if err := r.scanAllEndpoints(context.Background()); err != nil {
				t.Fatalf("scanAllEndpoints: %v", err)
			}
			sort.Strings(probed)
			want := []string{"keep-svc.example.com", "target.example.com"}
			if !slices.Equal(probed, want) {
				t.Errorf("probed hosts = %v, want %v", probed, want)
			}
		})
	}
}

func TestCleanupOrphanedCRs_DeletesFilteredNamespaceReports(t *testing.T) {
	for _, tt := range filterModes {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r := newFilterTestReconciler(t, &MockTLSChecker{})
			r.IncludeNamespaces = tt.include
			r.ExcludeNamespaces = tt.exclude

			if err := r.cleanupOrphanedCRs(ctx); err != nil {
				t.Fatalf("cleanupOrphanedCRs: %v", err)
			}

			for name, wantExists := range map[string]bool{"keep-svc": true, "target": true, "drop-svc": false} {
				var cr securityv1alpha1.TLSComplianceReport
				err := r.Get(ctx, client.ObjectKey{Name: name}, &cr)
				switch {
				case wantExists && err != nil:
					t.Errorf("expected %s to remain, got %v", name, err)
				case !wantExists && !apierrors.IsNotFound(err):
					t.Errorf("expected %s deleted, got err=%v", name, err)
				}
			}
		})
	}
}

func TestCleanupOrphanedCRs_NoFilterKeepsAllReports(t *testing.T) {
	ctx := context.Background()
	r := newFilterTestReconciler(t, &MockTLSChecker{})

	if err := r.cleanupOrphanedCRs(ctx); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	var list securityv1alpha1.TLSComplianceReportList
	if err := r.List(ctx, &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 3 {
		t.Errorf("expected 3 reports without a filter, got %d", len(list.Items))
	}
}
