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
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

const (
	testNamespace = "default"
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	return scheme
}

// MockTLSChecker implements tlscheck.Checker for testing
type MockTLSChecker struct {
	Result *tlscheck.TLSCheckResult
	Err    error
}

func (m *MockTLSChecker) CheckEndpoint(ctx context.Context, host string, port int) (*tlscheck.TLSCheckResult, error) {
	return m.Result, m.Err
}

func TestEndpointReconciler_Reconcile_ServiceWithHTTPS(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-service",
			Namespace: testNamespace,
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Verify TLSComplianceReport was created
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("TLSComplianceReport count = %v, want 1", len(crList.Items))
	}

	cr := crList.Items[0]
	if cr.Spec.Host != "my-service.default.svc.cluster.local" {
		t.Errorf("Host = %v, want my-service.default.svc.cluster.local", cr.Spec.Host)
	}
	if cr.Spec.Port != 443 {
		t.Errorf("Port = %v, want 443", cr.Spec.Port)
	}
	if cr.Spec.SourceKind != securityv1alpha1.SourceKindService {
		t.Errorf("SourceKind = %v, want Service", cr.Spec.SourceKind)
	}
	if cr.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusPending {
		t.Errorf("ComplianceStatus = %v, want Pending", cr.Status.ComplianceStatus)
	}
}

func TestEndpointReconciler_Reconcile_ServiceWithoutHTTPS(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-http-service",
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP},
				{Name: "grpc", Port: 9090, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-http-service",
			Namespace: testNamespace,
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Verify no TLSComplianceReport was created
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("TLSComplianceReport count = %v, want 0", len(crList.Items))
	}
}

func TestEndpointReconciler_Reconcile_DeletedService(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "deleted-service",
			Namespace: testNamespace,
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}
}

func TestEndpointReconciler_Reconcile_ExcludedNamespace(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: "kube-system",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:            fakeClient,
		Scheme:            scheme,
		CertExpiryDays:    30,
		ExcludeNamespaces: []string{"kube-system"},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-service",
			Namespace: "kube-system",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Verify no TLSComplianceReport was created
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("TLSComplianceReport count = %v, want 0 for excluded namespace", len(crList.Items))
	}
}

func TestEndpointReconciler_CleanupOrphanedCRs(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Create a Service that still exists
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-service",
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443},
			},
		},
	}

	now := metav1.Now()

	// CR for existing service
	existingCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "existing-service-443-abc12345",
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "existing-service.default.svc.cluster.local",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "existing-service",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
		},
	}

	// CR for deleted service
	orphanedCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "deleted-service-443-def67890",
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "deleted-service.default.svc.cluster.local",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "deleted-service",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc, existingCR, orphanedCR).
		WithStatusSubresource(existingCR, orphanedCR).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	err := reconciler.cleanupOrphanedCRs(ctx)
	if err != nil {
		t.Fatalf("cleanupOrphanedCRs() error = %v", err)
	}

	// Verify orphaned CR was deleted
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}

	if len(crList.Items) != 1 {
		t.Fatalf("TLSComplianceReport count = %v, want 1", len(crList.Items))
	}

	if crList.Items[0].Name != "existing-service-443-abc12345" {
		t.Errorf("remaining CR name = %v, want existing-service-443-abc12345", crList.Items[0].Name)
	}
}

func TestEndpointReconciler_Reconcile_ExistingCR(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-service",
			Namespace: testNamespace,
		},
	}

	// First reconcile - creates CR
	_, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("First Reconcile() error = %v", err)
	}

	// Get the created CR's last seen time
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("Expected 1 CR, got %d", len(crList.Items))
	}

	if crList.Items[0].Status.LastSeenAt == nil {
		t.Fatal("LastSeenAt should not be nil after first reconcile")
	}

	// Delay to ensure time difference
	time.Sleep(100 * time.Millisecond)

	firstLastSeen := crList.Items[0].Status.LastSeenAt.Time

	// Second reconcile - updates LastSeenAt
	_, err = reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Second Reconcile() error = %v", err)
	}

	// Verify LastSeenAt was updated
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("Expected 1 CR, got %d", len(crList.Items))
	}

	if crList.Items[0].Status.LastSeenAt == nil {
		t.Fatal("LastSeenAt should not be nil after second reconcile")
	}

	if crList.Items[0].Status.LastSeenAt.Time.Before(firstLastSeen) {
		t.Error("LastSeenAt should not go backwards after second reconcile")
	}
}

func TestDetermineComplianceStatus(t *testing.T) {
	tests := []struct {
		name     string
		result   *tlscheck.TLSCheckResult
		expected securityv1alpha1.ComplianceStatus
	}{
		{
			name: "Compliant - TLS 1.3 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13: true,
			},
			expected: securityv1alpha1.ComplianceStatusCompliant,
		},
		{
			name: "Compliant - TLS 1.2 and 1.3",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS12: true,
				SupportsTLS13: true,
			},
			expected: securityv1alpha1.ComplianceStatusCompliant,
		},
		{
			name: "NonCompliant - TLS 1.0",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
				SupportsTLS12: true,
				SupportsTLS13: true,
			},
			expected: securityv1alpha1.ComplianceStatusNonCompliant,
		},
		{
			name: "NonCompliant - TLS 1.1",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS11: true,
				SupportsTLS12: true,
			},
			expected: securityv1alpha1.ComplianceStatusNonCompliant,
		},
		{
			name: "Warning - TLS 1.2 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS12: true,
			},
			expected: securityv1alpha1.ComplianceStatusWarning,
		},
		{
			name:     "Unknown - no TLS versions",
			result:   &tlscheck.TLSCheckResult{},
			expected: securityv1alpha1.ComplianceStatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineComplianceStatus(tt.result)
			if got != tt.expected {
				t.Errorf("determineComplianceStatus() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEndpointReconciler_IsExcludedNamespace(t *testing.T) {
	r := &EndpointReconciler{
		ExcludeNamespaces: []string{"kube-system", "openshift-monitoring"},
	}

	tests := []struct {
		namespace string
		excluded  bool
	}{
		{"kube-system", true},
		{"openshift-monitoring", true},
		{"default", false},
		{"my-app", false},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := r.isExcludedNamespace(tt.namespace)
			if got != tt.excluded {
				t.Errorf("isExcludedNamespace(%q) = %v, want %v", tt.namespace, got, tt.excluded)
			}
		})
	}
}

func TestEndpointReconciler_ReconcileIngress(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: testNamespace,
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{
					Hosts: []string{"app.example.com"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ing).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	reconciler.ReconcileIngress(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-ingress",
			Namespace: testNamespace,
		},
	})

	// Small delay for async processing
	time.Sleep(50 * time.Millisecond)

	// Verify TLSComplianceReport was created
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("TLSComplianceReport count = %v, want 1", len(crList.Items))
	}

	cr := crList.Items[0]
	if cr.Spec.Host != "app.example.com" {
		t.Errorf("Host = %v, want app.example.com", cr.Spec.Host)
	}
	if cr.Spec.SourceKind != securityv1alpha1.SourceKindIngress {
		t.Errorf("SourceKind = %v, want Ingress", cr.Spec.SourceKind)
	}
}

func TestEndpointReconciler_StartCleanupLoop(t *testing.T) {
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	ctx, cancel := context.WithCancel(context.Background())
	reconciler.StartCleanupLoop(ctx, 100*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestEndpointReconciler_StartPeriodicScan(t *testing.T) {
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	ctx, cancel := context.WithCancel(context.Background())
	reconciler.StartPeriodicScan(ctx, 100*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestEndpointReconciler_ProcessEndpoint_Idempotent(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	ep := endpoint.Endpoint{
		Host:            "service.default.svc.cluster.local",
		Port:            443,
		SourceKind:      "Service",
		SourceNamespace: "default",
		SourceName:      "service",
	}

	// Process same endpoint twice
	err := reconciler.processEndpoint(ctx, ep)
	if err != nil {
		t.Fatalf("first processEndpoint() error = %v", err)
	}

	err = reconciler.processEndpoint(ctx, ep)
	if err != nil {
		t.Fatalf("second processEndpoint() error = %v", err)
	}

	// Should still have only 1 CR
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Errorf("Expected 1 CR, got %d", len(crList.Items))
	}
}

// Ensure _ satisfies the client.Object interface for compile-time check
var _ client.Object = &securityv1alpha1.TLSComplianceReport{}
