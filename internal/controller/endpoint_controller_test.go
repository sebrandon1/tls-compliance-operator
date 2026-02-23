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
	"fmt"
	"sync"
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

func (m *MockTLSChecker) CheckEndpoint(_ context.Context, _ string, _ int) (*tlscheck.TLSCheckResult, error) {
	return m.Result, m.Err
}

// SequencedMockTLSChecker returns different results on successive calls
type SequencedMockTLSChecker struct {
	Results []*tlscheck.TLSCheckResult
	Errors  []error
	callIdx int
	mu      sync.Mutex
}

func (s *SequencedMockTLSChecker) CheckEndpoint(_ context.Context, _ string, _ int) (*tlscheck.TLSCheckResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.callIdx
	if idx >= len(s.Results) {
		idx = len(s.Results) - 1
	}
	s.callIdx++
	return s.Results[idx], s.Errors[idx]
}

func (s *SequencedMockTLSChecker) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callIdx
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
	if cr.Spec.Host != "my-service.default" {
		t.Errorf("Host = %v, want my-service.default", cr.Spec.Host)
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

func TestEndpointReconciler_Reconcile_IncludeNamespaces(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Service in included namespace
	includedSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "included-service",
			Namespace: "my-app",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	// Service in non-included namespace
	excludedSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "excluded-service",
			Namespace: "other-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(includedSvc, excludedSvc).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:            fakeClient,
		Scheme:            scheme,
		CertExpiryDays:    30,
		IncludeNamespaces: []string{"my-app"},
	}

	// Reconcile included namespace - should create CR
	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "included-service", Namespace: "my-app"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Reconcile non-included namespace - should be skipped
	result, err = reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "excluded-service", Namespace: "other-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Only 1 CR should exist (from included namespace)
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("TLSComplianceReport count = %v, want 1", len(crList.Items))
	}
	if crList.Items[0].Spec.SourceNamespace != "my-app" {
		t.Errorf("SourceNamespace = %v, want my-app", crList.Items[0].Spec.SourceNamespace)
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
			Host:            "existing-service.default",
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
			Host:            "deleted-service.default",
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
			name: "Compliant - TLS 1.2 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS12: true,
			},
			expected: securityv1alpha1.ComplianceStatusCompliant,
		},
		{
			name: "Compliant - all versions (Old profile)",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
				SupportsTLS11: true,
				SupportsTLS12: true,
				SupportsTLS13: true,
			},
			expected: securityv1alpha1.ComplianceStatusCompliant,
		},
		{
			name: "Compliant - TLS 1.0 with 1.2",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
				SupportsTLS12: true,
			},
			expected: securityv1alpha1.ComplianceStatusCompliant,
		},
		{
			name: "NonCompliant - TLS 1.0 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
			},
			expected: securityv1alpha1.ComplianceStatusNonCompliant,
		},
		{
			name: "NonCompliant - TLS 1.1 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS11: true,
			},
			expected: securityv1alpha1.ComplianceStatusNonCompliant,
		},
		{
			name: "NonCompliant - TLS 1.0 and 1.1 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
				SupportsTLS11: true,
			},
			expected: securityv1alpha1.ComplianceStatusNonCompliant,
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

func TestIsQuantumReady(t *testing.T) {
	tests := []struct {
		name     string
		curves   map[string]string
		expected bool
	}{
		{
			name:     "nil map",
			curves:   nil,
			expected: false,
		},
		{
			name:     "empty map",
			curves:   map[string]string{},
			expected: false,
		},
		{
			name:     "classical only",
			curves:   map[string]string{"TLS 1.2": "X25519", "TLS 1.3": "X25519"},
			expected: false,
		},
		{
			name:     "PQC on TLS 1.3",
			curves:   map[string]string{"TLS 1.2": "X25519", "TLS 1.3": "X25519MLKEM768"},
			expected: true,
		},
		{
			name:     "PQC only version",
			curves:   map[string]string{"TLS 1.3": "X25519MLKEM768"},
			expected: true,
		},
		{
			name:     "P-256 only",
			curves:   map[string]string{"TLS 1.2": "P-256"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isQuantumReady(tt.curves)
			if got != tt.expected {
				t.Errorf("isQuantumReady() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEndpointReconciler_IsNamespaceFiltered_ExcludeMode(t *testing.T) {
	r := &EndpointReconciler{
		ExcludeNamespaces: []string{"kube-system", "openshift-monitoring"},
	}

	tests := []struct {
		namespace string
		filtered  bool
	}{
		{"kube-system", true},
		{"openshift-monitoring", true},
		{"default", false},
		{"my-app", false},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := r.isNamespaceFiltered(tt.namespace)
			if got != tt.filtered {
				t.Errorf("isNamespaceFiltered(%q) = %v, want %v", tt.namespace, got, tt.filtered)
			}
		})
	}
}

func TestEndpointReconciler_IsNamespaceFiltered_IncludeMode(t *testing.T) {
	r := &EndpointReconciler{
		IncludeNamespaces: []string{"my-app", "staging"},
	}

	tests := []struct {
		namespace string
		filtered  bool
	}{
		{"my-app", false},
		{"staging", false},
		{"default", true},
		{"kube-system", true},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := r.isNamespaceFiltered(tt.namespace)
			if got != tt.filtered {
				t.Errorf("isNamespaceFiltered(%q) = %v, want %v", tt.namespace, got, tt.filtered)
			}
		})
	}
}

func TestEndpointReconciler_IsNamespaceFiltered_IncludeOverridesExclude(t *testing.T) {
	r := &EndpointReconciler{
		IncludeNamespaces: []string{"my-app"},
		ExcludeNamespaces: []string{"my-app", "kube-system"},
	}

	tests := []struct {
		namespace string
		filtered  bool
	}{
		{"my-app", false},     // included, even though also in exclude list
		{"kube-system", true}, // not in include list, so filtered
		{"default", true},     // not in include list, so filtered
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := r.isNamespaceFiltered(tt.namespace)
			if got != tt.filtered {
				t.Errorf("isNamespaceFiltered(%q) = %v, want %v", tt.namespace, got, tt.filtered)
			}
		})
	}
}

func TestEndpointReconciler_IsNamespaceFiltered_NeitherSet(t *testing.T) {
	r := &EndpointReconciler{}

	tests := []struct {
		namespace string
		filtered  bool
	}{
		{"default", false},
		{"kube-system", false},
		{"my-app", false},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := r.isNamespaceFiltered(tt.namespace)
			if got != tt.filtered {
				t.Errorf("isNamespaceFiltered(%q) = %v, want %v", tt.namespace, got, tt.filtered)
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
		Host:            "service.default",
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

func TestEndpointReconciler_ScanPodEndpoints(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-pod",
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.1.5",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	err := reconciler.scanPodEndpoints(ctx)
	if err != nil {
		t.Fatalf("scanPodEndpoints() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("TLSComplianceReport count = %d, want 1", len(crList.Items))
	}

	cr := crList.Items[0]
	if cr.Spec.SourceKind != securityv1alpha1.SourceKindPod {
		t.Errorf("SourceKind = %v, want Pod", cr.Spec.SourceKind)
	}
	if cr.Spec.Host != "10.244.1.5" {
		t.Errorf("Host = %v, want 10.244.1.5", cr.Spec.Host)
	}
	if cr.Spec.Port != 443 {
		t.Errorf("Port = %v, want 443", cr.Spec.Port)
	}
	if cr.Spec.SourceName != "tls-pod" {
		t.Errorf("SourceName = %v, want tls-pod", cr.Spec.SourceName)
	}
}

func TestEndpointReconciler_ScanPodEndpoints_NamespaceFiltered(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-pod",
			Namespace: "kube-system",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:            fakeClient,
		Scheme:            scheme,
		CertExpiryDays:    30,
		ExcludeNamespaces: []string{"kube-system"},
	}

	err := reconciler.scanPodEndpoints(ctx)
	if err != nil {
		t.Fatalf("scanPodEndpoints() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("TLSComplianceReport count = %d, want 0 for filtered namespace", len(crList.Items))
	}
}

func TestEndpointReconciler_ScanPodEndpoints_NonRunningPod(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-pod",
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending, PodIP: "10.244.1.5"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	err := reconciler.scanPodEndpoints(ctx)
	if err != nil {
		t.Fatalf("scanPodEndpoints() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("TLSComplianceReport count = %d, want 0 for non-running pod", len(crList.Items))
	}
}

func TestEndpointReconciler_SourceResourceExists_Pod(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-pod",
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app"},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		Build()

	reconciler := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Existing pod should return true
	exists, err := reconciler.sourceResourceExists(ctx, securityv1alpha1.TLSComplianceReportSpec{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: testNamespace,
		SourceName:      "existing-pod",
	})
	if err != nil {
		t.Fatalf("sourceResourceExists() error = %v", err)
	}
	if !exists {
		t.Error("sourceResourceExists() = false, want true for existing pod")
	}

	// Deleted pod should return false
	exists, err = reconciler.sourceResourceExists(ctx, securityv1alpha1.TLSComplianceReportSpec{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: testNamespace,
		SourceName:      "deleted-pod",
	})
	if err != nil {
		t.Fatalf("sourceResourceExists() error = %v", err)
	}
	if exists {
		t.Error("sourceResourceExists() = true, want false for deleted pod")
	}
}

func TestEndpointReconciler_ScanPodEndpoints_HostNetworkLabel(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hostnet-pod",
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{
				{
					Name: "app",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "192.168.1.100",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	err := reconciler.scanPodEndpoints(ctx)
	if err != nil {
		t.Fatalf("scanPodEndpoints() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("TLSComplianceReport count = %d, want 1", len(crList.Items))
	}

	cr := crList.Items[0]
	labelVal, ok := cr.Labels["tls-compliance.telco.openshift.io/host-network"]
	if !ok {
		t.Error("expected host-network label to be set on CR")
	}
	if labelVal != "true" {
		t.Errorf("host-network label = %q, want true", labelVal)
	}
}

func TestEndpointReconciler_RetryThenSuccess(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Pre-create the CR that performTLSCheck expects
	crName := "retry-test-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "test.example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "test-service",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			LastSeenAt:       &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	checker := &SequencedMockTLSChecker{
		Results: []*tlscheck.TLSCheckResult{
			{FailureReason: tlscheck.FailureReasonTimeout},
			{SupportsTLS12: true, SupportsTLS13: true, CipherSuites: map[string][]string{}},
		},
		Errors: []error{
			fmt.Errorf("connection timed out"),
			nil,
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   10 * time.Millisecond,
	}

	reconciler.performTLSCheck(ctx, crName, "test.example.com", 443)

	// Should have called checker twice (1 failure + 1 success)
	if checker.CallCount() != 2 {
		t.Errorf("expected 2 calls, got %d", checker.CallCount())
	}

	// Verify final CR status is Compliant
	var updatedCR securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &updatedCR); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}
	if updatedCR.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusCompliant {
		t.Errorf("ComplianceStatus = %v, want Compliant", updatedCR.Status.ComplianceStatus)
	}
	if updatedCR.Status.RetryCount != 0 {
		t.Errorf("RetryCount = %d, want 0 (cleared after completion)", updatedCR.Status.RetryCount)
	}
	if updatedCR.Status.NextRetryAt != nil {
		t.Error("NextRetryAt should be nil after completion")
	}
}

func TestEndpointReconciler_RetryExhausted(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	crName := "retry-exhausted-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "unreachable.example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "unreachable-service",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			LastSeenAt:       &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	// All attempts fail with transient error
	checker := &SequencedMockTLSChecker{
		Results: []*tlscheck.TLSCheckResult{
			{FailureReason: tlscheck.FailureReasonTimeout},
			{FailureReason: tlscheck.FailureReasonTimeout},
			{FailureReason: tlscheck.FailureReasonTimeout},
		},
		Errors: []error{
			fmt.Errorf("timeout 1"),
			fmt.Errorf("timeout 2"),
			fmt.Errorf("timeout 3"),
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     2,
		RetryBackoff:   10 * time.Millisecond,
	}

	reconciler.performTLSCheck(ctx, crName, "unreachable.example.com", 443)

	// Should have called checker 3 times (1 initial + 2 retries)
	if checker.CallCount() != 3 {
		t.Errorf("expected 3 calls, got %d", checker.CallCount())
	}

	// Verify final CR status is Timeout
	var updatedCR securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &updatedCR); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}
	if updatedCR.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusTimeout {
		t.Errorf("ComplianceStatus = %v, want Timeout", updatedCR.Status.ComplianceStatus)
	}
	if updatedCR.Status.RetryCount != 0 {
		t.Errorf("RetryCount = %d, want 0 (cleared after completion)", updatedCR.Status.RetryCount)
	}
}

func TestEndpointReconciler_NoRetryOnNoTLS(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	crName := "no-retry-notls-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "notls.example.com",
			Port:            80,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "notls-service",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			LastSeenAt:       &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	checker := &SequencedMockTLSChecker{
		Results: []*tlscheck.TLSCheckResult{
			{FailureReason: tlscheck.FailureReasonNoTLS},
		},
		Errors: []error{
			fmt.Errorf("not TLS"),
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   10 * time.Millisecond,
	}

	reconciler.performTLSCheck(ctx, crName, "notls.example.com", 80)

	// Should only call once — NoTLS is not transient
	if checker.CallCount() != 1 {
		t.Errorf("expected 1 call (no retry for NoTLS), got %d", checker.CallCount())
	}

	var updatedCR securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &updatedCR); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}
	if updatedCR.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusNoTLS {
		t.Errorf("ComplianceStatus = %v, want NoTLS", updatedCR.Status.ComplianceStatus)
	}
}

func TestEndpointReconciler_NoRetryOnMutualTLS(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	crName := "no-retry-mtls-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "mtls.example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "mtls-service",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			LastSeenAt:       &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	checker := &SequencedMockTLSChecker{
		Results: []*tlscheck.TLSCheckResult{
			{FailureReason: tlscheck.FailureReasonMutualTLSRequired},
		},
		Errors: []error{
			fmt.Errorf("mutual TLS required"),
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   10 * time.Millisecond,
	}

	reconciler.performTLSCheck(ctx, crName, "mtls.example.com", 443)

	// Should only call once — MutualTLSRequired is not transient
	if checker.CallCount() != 1 {
		t.Errorf("expected 1 call (no retry for MutualTLSRequired), got %d", checker.CallCount())
	}

	var updatedCR securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &updatedCR); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}
	if updatedCR.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusMutualTLSRequired {
		t.Errorf("ComplianceStatus = %v, want MutualTLSRequired", updatedCR.Status.ComplianceStatus)
	}
}

func TestEndpointReconciler_RetryDisabled(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	crName := "retry-disabled-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "timeout.example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "timeout-service",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			LastSeenAt:       &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	checker := &SequencedMockTLSChecker{
		Results: []*tlscheck.TLSCheckResult{
			{FailureReason: tlscheck.FailureReasonTimeout},
		},
		Errors: []error{
			fmt.Errorf("timeout"),
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     0, // retries disabled
		RetryBackoff:   10 * time.Millisecond,
	}

	reconciler.performTLSCheck(ctx, crName, "timeout.example.com", 443)

	// Should only call once — retries disabled
	if checker.CallCount() != 1 {
		t.Errorf("expected 1 call (retries disabled), got %d", checker.CallCount())
	}

	var updatedCR securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &updatedCR); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}
	if updatedCR.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusTimeout {
		t.Errorf("ComplianceStatus = %v, want Timeout", updatedCR.Status.ComplianceStatus)
	}
}

// Ensure _ satisfies the client.Object interface for compile-time check
var _ client.Object = &securityv1alpha1.TLSComplianceReport{}
