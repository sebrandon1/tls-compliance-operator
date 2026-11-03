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
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

var (
	httpRouteGVK = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	grpcRouteGVK = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GRPCRoute"}
)

func namespacedUnstructured(gvk schema.GroupVersionKind, name string, spec map[string]any) *unstructured.Unstructured {
	obj := newUnstructured(gvk)
	obj.SetName(name)
	obj.SetNamespace(testNamespace)
	obj.Object["spec"] = spec
	return obj
}

// Regression test for #650: a Service used to shadow every other kind with
// the same namespace and name, so only the Service was ever reconciled.
func TestReconcile_SameNameKindsAreNotShadowed(t *testing.T) {
	ctx := context.Background()
	const name = "app"
	scheme := newTestScheme()

	objs := []client.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			}},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"ingress.example.com"}},
			}},
		},
		namespacedUnstructured(routeGVK, name, map[string]any{
			"host": "route.example.com",
			"tls":  map[string]any{"termination": "edge"},
		}),
		namespacedUnstructured(httpRouteGVK, name, map[string]any{"hostnames": []any{"httproute.example.com"}}),
		namespacedUnstructured(grpcRouteGVK, name, map[string]any{"hostnames": []any{"grpcroute.example.com"}}),
	}
	r := &EndpointReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(objs...).
			WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
			Build(),
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: testNamespace}}
	for kind, reconcileFn := range map[string]reconcile.Func{
		"Service":   r.reconcileService,
		"Ingress":   r.reconcileIngress,
		"Route":     r.reconcileRoute,
		"HTTPRoute": r.gatewayReconciler(httpRouteGVK),
		"GRPCRoute": r.gatewayReconciler(grpcRouteGVK),
	} {
		if _, err := reconcileFn(ctx, req); err != nil {
			t.Fatalf("reconcile %s: %v", kind, err)
		}
	}
	r.DrainInFlightChecks(ctx)

	var reports securityv1alpha1.TLSComplianceReportList
	if err := r.List(ctx, &reports); err != nil {
		t.Fatalf("list reports: %v", err)
	}
	hostsByKind := map[securityv1alpha1.SourceKind]string{}
	for _, cr := range reports.Items {
		if cr.Spec.SourceName != name {
			t.Errorf("report %s: sourceName = %q, want %q", cr.Name, cr.Spec.SourceName, name)
		}
		hostsByKind[cr.Spec.SourceKind] = cr.Spec.Host
	}
	want := map[securityv1alpha1.SourceKind]string{
		securityv1alpha1.SourceKindService:   name + "." + testNamespace,
		securityv1alpha1.SourceKindIngress:   "ingress.example.com",
		securityv1alpha1.SourceKindRoute:     "route.example.com",
		securityv1alpha1.SourceKindHTTPRoute: "httproute.example.com",
		securityv1alpha1.SourceKindGRPCRoute: "grpcroute.example.com",
	}
	for kind, host := range want {
		if got, ok := hostsByKind[kind]; !ok {
			t.Errorf("no report for %s %q", kind, name)
		} else if got != host {
			t.Errorf("%s report host = %q, want %q", kind, got, host)
		}
	}
}

func TestReconcileObject_GetErrors(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "svc", Namespace: testNamespace}}
	boom := errors.New("boom")

	tests := []struct {
		name    string
		getErr  error
		wantErr error
	}{
		{"not found is ignored", nil, nil},
		{"other errors are returned for retry", boom, boom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.getErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
						return tt.getErr
					},
				})
			}
			r := &EndpointReconciler{Client: builder.Build(), Scheme: scheme}

			_, err := r.reconcileService(ctx, req)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("reconcileService() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestReconcileReport_WithoutRescanAnnotationIsNoop(t *testing.T) {
	ctx := context.Background()
	checker := &MockTLSChecker{}
	r := newFilterTestReconciler(t, checker)

	if _, err := r.reconcileReport(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "keep-svc"}}); err != nil {
		t.Fatalf("reconcileReport() error = %v", err)
	}
	r.DrainInFlightChecks(ctx)
	if got := checker.callCount.Load(); got != 0 {
		t.Errorf("TLS checks = %d, want 0 without the rescan annotation", got)
	}
}

func TestHasRescanAnnotation(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{"no annotations", nil, false},
		{"other annotation", map[string]string{"example.com/other": "true"}, false},
		{"rescan with empty value", map[string]string{securityv1alpha1.RescanAnnotation: ""}, true},
		{"rescan", map[string]string{securityv1alpha1.RescanAnnotation: "true"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := &securityv1alpha1.TLSComplianceReport{ObjectMeta: metav1.ObjectMeta{Annotations: tt.annotations}}
			if got := hasRescanAnnotation(cr); got != tt.want {
				t.Errorf("hasRescanAnnotation() = %v, want %v", got, tt.want)
			}
		})
	}
}

// SetupWithManager must register every per-kind controller, including the
// optional Route and Gateway API ones, without a type or option error.
func TestSetupWithManager_RegistersPerKindControllers(t *testing.T) {
	mgr, err := ctrl.NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, ctrl.Options{
		Scheme:     newTestScheme(),
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	r := &EndpointReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		Workers:           2,
		RouteAPIAvailable: true,
		GatewayGVKs:       []schema.GroupVersionKind{httpRouteGVK, grpcRouteGVK},
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
}
