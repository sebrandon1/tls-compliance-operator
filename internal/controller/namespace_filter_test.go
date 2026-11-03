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
	"strings"
	"sync"
	"testing"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
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
			if got := endpointsTotalSum(t); got != 2 {
				t.Errorf("endpoints_total sum = %v, want 2 (filtered report must not be counted)", got)
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

func countReports(t *testing.T, r *EndpointReconciler) int {
	t.Helper()
	var list securityv1alpha1.TLSComplianceReportList
	if err := r.List(context.Background(), &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	return len(list.Items)
}

func TestReconcile_NamespacedRequestsHonorFilter(t *testing.T) {
	for _, tt := range filterModes {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r := newFilterTestReconciler(t, &MockTLSChecker{})
			r.IncludeNamespaces = tt.include
			r.ExcludeNamespaces = tt.exclude

			for _, ns := range []string{"keep", "drop"} {
				svc := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "https", Namespace: ns},
					Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
						{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
					}},
				}
				if err := r.Create(ctx, svc); err != nil {
					t.Fatalf("create service: %v", err)
				}
			}

			before := countReports(t, r)
			for _, ns := range []string{"keep", "drop"} {
				req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "https", Namespace: ns}}
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatalf("Reconcile %s: %v", ns, err)
				}
			}
			if got := countReports(t, r) - before; got != 1 {
				t.Errorf("new reports = %d, want 1 (only the service in keep)", got)
			}
		})
	}
}

func TestReconcile_TargetUnderNamespaceFilter(t *testing.T) {
	for _, tt := range filterModes {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r := newFilterTestReconciler(t, &MockTLSChecker{})
			r.IncludeNamespaces = tt.include
			r.ExcludeNamespaces = tt.exclude

			target := &securityv1alpha1.TLSComplianceTarget{
				ObjectMeta: metav1.ObjectMeta{Name: "new-target"},
				Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "new-target.example.com"},
			}
			if err := r.Create(ctx, target); err != nil {
				t.Fatalf("create target: %v", err)
			}

			before := countReports(t, r)
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "new-target"}}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if got := countReports(t, r) - before; got != 1 {
				t.Errorf("new reports = %d, want 1 for the Target", got)
			}
		})
	}
}

func TestReconcile_RescanUnderNamespaceFilter(t *testing.T) {
	for _, tt := range filterModes {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r := newFilterTestReconciler(t, &MockTLSChecker{
				Result: &tlscheck.TLSCheckResult{SupportsTLS12: true, SupportsTLS13: true},
			})
			r.IncludeNamespaces = tt.include
			r.ExcludeNamespaces = tt.exclude
			recorder := events.NewFakeRecorder(10)
			r.Recorder = recorder

			wantConsumed := map[string]bool{"keep-svc": true, "target": true, "drop-svc": false}
			for name := range wantConsumed {
				if err := r.updateWithRetry(ctx, name, func(cr *securityv1alpha1.TLSComplianceReport) {
					cr.Annotations = map[string]string{securityv1alpha1.RescanAnnotation: "true"}
				}); err != nil {
					t.Fatalf("annotate %s: %v", name, err)
				}
				if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
					t.Fatalf("Reconcile %s: %v", name, err)
				}
			}

			for name, consumed := range wantConsumed {
				var cr securityv1alpha1.TLSComplianceReport
				if err := r.Get(ctx, client.ObjectKey{Name: name}, &cr); err != nil {
					t.Fatalf("get %s: %v", name, err)
				}
				if _, pending := cr.Annotations[securityv1alpha1.RescanAnnotation]; pending == consumed {
					t.Errorf("%s: rescan annotation still present = %v, want %v", name, pending, !consumed)
				}
			}
			if !drainedEventContains(recorder, EventReasonRescanSkipped) {
				t.Errorf("expected a %s event for the filtered report", EventReasonRescanSkipped)
			}
		})
	}
}

func endpointsTotalSum(t *testing.T) float64 {
	t.Helper()
	var sum float64
	for _, status := range []securityv1alpha1.ComplianceStatus{
		securityv1alpha1.ComplianceStatusCompliant, securityv1alpha1.ComplianceStatusNonCompliant,
		securityv1alpha1.ComplianceStatusWarning, securityv1alpha1.ComplianceStatusUnreachable,
		securityv1alpha1.ComplianceStatusTimeout, securityv1alpha1.ComplianceStatusClosed,
		securityv1alpha1.ComplianceStatusFiltered, securityv1alpha1.ComplianceStatusNoTLS,
		securityv1alpha1.ComplianceStatusPlaintextHTTP, securityv1alpha1.ComplianceStatusMutualTLSRequired,
		securityv1alpha1.ComplianceStatusPending, securityv1alpha1.ComplianceStatusUnknown,
	} {
		m := &dto.Metric{}
		if err := metrics.EndpointsTotal.WithLabelValues(string(status)).Write(m); err != nil {
			t.Fatalf("read endpoints_total: %v", err)
		}
		sum += m.GetGauge().GetValue()
	}
	return sum
}

func drainedEventContains(recorder *events.FakeRecorder, substr string) bool {
	for {
		select {
		case e := <-recorder.Events:
			if strings.Contains(e, substr) {
				return true
			}
		default:
			return false
		}
	}
}

func TestReportsInFilter(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		*filterTestReport("keep-svc", securityv1alpha1.SourceKindService, "keep", "svc"),
		*filterTestReport("drop-svc", securityv1alpha1.SourceKindService, "drop", "svc"),
		*filterTestReport("target", securityv1alpha1.SourceKindTarget, "cluster-scoped", "tgt"),
	}
	names := func(rs []securityv1alpha1.TLSComplianceReport) []string {
		out := make([]string, 0, len(rs))
		for i := range rs {
			out = append(out, rs[i].Name)
		}
		return out
	}

	if got := (&EndpointReconciler{}).ReportsInFilter(reports); len(got) != len(reports) {
		t.Errorf("no filter: kept %v, want all reports", names(got))
	}
	for _, tt := range filterModes {
		t.Run(tt.name, func(t *testing.T) {
			r := &EndpointReconciler{IncludeNamespaces: tt.include, ExcludeNamespaces: tt.exclude}
			if got, want := names(r.ReportsInFilter(reports)), []string{"keep-svc", "target"}; !slices.Equal(got, want) {
				t.Errorf("kept %v, want %v", got, want)
			}
		})
	}
}
