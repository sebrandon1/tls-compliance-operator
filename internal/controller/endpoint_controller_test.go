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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	dto "github.com/prometheus/client_model/go"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
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
	Result    *tlscheck.TLSCheckResult
	Err       error
	callCount atomic.Int32
}

func (m *MockTLSChecker) CheckEndpoint(_ context.Context, _ string, _ int) (*tlscheck.TLSCheckResult, error) {
	m.callCount.Add(1)
	return m.Result, m.Err
}

func (m *MockTLSChecker) CheckCount() int32 {
	return m.callCount.Load()
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

func TestEndpointReconciler_Reconcile_ExternalNameService(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-api",
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "api.vendor.example.com",
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
			Name:      "external-api",
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

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("TLSComplianceReport count = %v, want 1", len(crList.Items))
	}

	cr := crList.Items[0]
	if cr.Spec.Host != "api.vendor.example.com" {
		t.Errorf("Host = %v, want api.vendor.example.com", cr.Spec.Host)
	}
	if cr.Spec.Port != 443 {
		t.Errorf("Port = %v, want 443", cr.Spec.Port)
	}
	if cr.Spec.SourceKind != securityv1alpha1.SourceKindService {
		t.Errorf("SourceKind = %v, want Service", cr.Spec.SourceKind)
	}
	if cr.Spec.SourceName != "external-api" {
		t.Errorf("SourceName = %v, want external-api", cr.Spec.SourceName)
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
		ExcludeNamespaces: map[string]bool{"kube-system": true},
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
		IncludeNamespaces: map[string]bool{"my-app": true},
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
			name: "Warning - all versions (Old profile)",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
				SupportsTLS11: true,
				SupportsTLS12: true,
				SupportsTLS13: true,
			},
			expected: securityv1alpha1.ComplianceStatusWarning,
		},
		{
			name: "Warning - TLS 1.0 with 1.2",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
				SupportsTLS12: true,
			},
			expected: securityv1alpha1.ComplianceStatusWarning,
		},
		{
			name: "Warning - TLS 1.1 with 1.3",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS11: true,
				SupportsTLS13: true,
			},
			expected: securityv1alpha1.ComplianceStatusWarning,
		},
		{
			name: "Warning - SSL 3.0 with TLS 1.2",
			result: &tlscheck.TLSCheckResult{
				SupportsSSL30: true,
				SupportsTLS12: true,
			},
			expected: securityv1alpha1.ComplianceStatusWarning,
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
		{
			name:     "hybrid SecP256r1MLKEM768",
			curves:   map[string]string{"TLS 1.3": "SecP256r1MLKEM768"},
			expected: true,
		},
		{
			name:     "hybrid SecP384r1MLKEM1024",
			curves:   map[string]string{"TLS 1.3": "SecP384r1MLKEM1024"},
			expected: true,
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

func TestDeterminePQCReadiness(t *testing.T) {
	tests := []struct {
		name     string
		result   *tlscheck.TLSCheckResult
		expected securityv1alpha1.PQCReadiness
	}{
		{
			name: "PQCReady - TLS 1.3 with MLKEM",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13:    true,
				SupportsTLS12:    true,
				NegotiatedCurves: map[string]string{"TLS 1.3": "X25519MLKEM768", "TLS 1.2": "X25519"},
			},
			expected: securityv1alpha1.PQCReadinessPQCReady,
		},
		{
			name: "TLS13Capable - TLS 1.3 without MLKEM",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13:    true,
				SupportsTLS12:    true,
				NegotiatedCurves: map[string]string{"TLS 1.3": "X25519", "TLS 1.2": "X25519"},
			},
			expected: securityv1alpha1.PQCReadinessTLS13Capable,
		},
		{
			name: "LegacyTLS - TLS 1.2 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS12:    true,
				NegotiatedCurves: map[string]string{"TLS 1.2": "P-256"},
			},
			expected: securityv1alpha1.PQCReadinessLegacyTLS,
		},
		{
			name: "LegacyTLS - TLS 1.0 and 1.1 only",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS10: true,
				SupportsTLS11: true,
			},
			expected: securityv1alpha1.PQCReadinessLegacyTLS,
		},
		{
			name:     "NoPQC - no TLS detected",
			result:   &tlscheck.TLSCheckResult{},
			expected: securityv1alpha1.PQCReadinessNoPQC,
		},
		{
			name: "PQCReady - TLS 1.3 only with MLKEM",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13:    true,
				NegotiatedCurves: map[string]string{"TLS 1.3": "X25519MLKEM768"},
			},
			expected: securityv1alpha1.PQCReadinessPQCReady,
		},
		{
			name: "PQCReady - active probe detected MLKEM but passive negotiation used classical",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13:    true,
				SupportsTLS12:    true,
				NegotiatedCurves: map[string]string{"TLS 1.3": "X25519", "TLS 1.2": "P-256"},
				MLKEMSupported:   true,
			},
			expected: securityv1alpha1.PQCReadinessPQCReady,
		},
		{
			name: "TLS13Capable - active probe did not detect MLKEM",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13:    true,
				NegotiatedCurves: map[string]string{"TLS 1.3": "X25519"},
				MLKEMSupported:   false,
			},
			expected: securityv1alpha1.PQCReadinessTLS13Capable,
		},
		{
			name: "PQCReady - hybrid SecP256r1MLKEM768",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13:    true,
				NegotiatedCurves: map[string]string{"TLS 1.3": "SecP256r1MLKEM768"},
			},
			expected: securityv1alpha1.PQCReadinessPQCReady,
		},
		{
			name: "PQCReady - hybrid SecP384r1MLKEM1024",
			result: &tlscheck.TLSCheckResult{
				SupportsTLS13:    true,
				NegotiatedCurves: map[string]string{"TLS 1.3": "SecP384r1MLKEM1024"},
			},
			expected: securityv1alpha1.PQCReadinessPQCReady,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determinePQCReadiness(tt.result)
			if got != tt.expected {
				t.Errorf("determinePQCReadiness() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEndpointReconciler_IsNamespaceFiltered_ExcludeMode(t *testing.T) {
	r := &EndpointReconciler{
		ExcludeNamespaces: map[string]bool{"kube-system": true, "openshift-monitoring": true},
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
		IncludeNamespaces: map[string]bool{"my-app": true, "staging": true},
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
		IncludeNamespaces: map[string]bool{"my-app": true},
		ExcludeNamespaces: map[string]bool{"my-app": true, "kube-system": true},
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

	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-ingress",
			Namespace: testNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

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
	elected := make(chan struct{})
	close(elected)
	reconciler.StartPeriodicScan(ctx, 100*time.Millisecond, elected)
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
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "service",
	}

	// Process same endpoint twice
	err := reconciler.processEndpoint(ctx, &ep)
	if err != nil {
		t.Fatalf("first processEndpoint() error = %v", err)
	}

	err = reconciler.processEndpoint(ctx, &ep)
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

func TestProcessEndpoint_RetriesPendingCR(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{
			SupportsTLS12: true,
			SupportsTLS13: true,
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		Workers:        1,
		ManagerCtx:     ctx,
	}

	ep := endpoint.Endpoint{
		Host:            "pending.example",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "pending-svc",
	}

	crName := endpoint.GenerateCRName(&ep)
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: ep.Host, Port: ep.Port,
			SourceKind: ep.SourceKind, SourceNamespace: ep.SourceNamespace, SourceName: ep.SourceName,
		},
	}
	if err := fakeClient.Create(ctx, cr); err != nil {
		t.Fatalf("failed to create CR: %v", err)
	}
	cr.Status = securityv1alpha1.TLSComplianceReportStatus{
		ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
		CheckCount:       0,
		FirstSeenAt:      &now,
		LastSeenAt:       &now,
	}
	if err := fakeClient.Status().Update(ctx, cr); err != nil {
		t.Fatalf("failed to update CR status: %v", err)
	}

	err := reconciler.processEndpoint(ctx, &ep)
	if err != nil {
		t.Fatalf("processEndpoint() error = %v", err)
	}

	// Wait for the async TLS check goroutine to complete
	time.Sleep(500 * time.Millisecond)

	var updated securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &updated); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}

	if updated.Status.ComplianceStatus == securityv1alpha1.ComplianceStatusPending {
		t.Error("CR should no longer be Pending after processEndpoint retried the check")
	}
}

func TestProcessEndpoint_PendingWithCheckCountSkipsRetry(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{
			SupportsTLS12: true,
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		Workers:        1,
		ManagerCtx:     ctx,
	}

	ep := endpoint.Endpoint{
		Host:            "pending-checked.example",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "pending-checked-svc",
	}

	crName := endpoint.GenerateCRName(&ep)
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: ep.Host, Port: ep.Port,
			SourceKind: ep.SourceKind, SourceNamespace: ep.SourceNamespace, SourceName: ep.SourceName,
		},
	}
	if err := fakeClient.Create(ctx, cr); err != nil {
		t.Fatalf("failed to create CR: %v", err)
	}
	cr.Status = securityv1alpha1.TLSComplianceReportStatus{
		ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
		CheckCount:       1,
		FirstSeenAt:      &now,
		LastSeenAt:       &now,
	}
	if err := fakeClient.Status().Update(ctx, cr); err != nil {
		t.Fatalf("failed to update CR status: %v", err)
	}

	checkerCallsBefore := checker.CheckCount()
	err := reconciler.processEndpoint(ctx, &ep)
	if err != nil {
		t.Fatalf("processEndpoint() error = %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if checker.CheckCount() != checkerCallsBefore {
		t.Error("TLS checker should not be called for Pending CR with CheckCount > 0")
	}
}

func TestProcessEndpoint_NonPendingSkipsRetry(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{
			SupportsTLS12: true,
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		Workers:        1,
		ManagerCtx:     ctx,
	}

	ep := endpoint.Endpoint{
		Host:            "compliant.example",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "compliant-svc",
	}

	crName := endpoint.GenerateCRName(&ep)
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: ep.Host, Port: ep.Port,
			SourceKind: ep.SourceKind, SourceNamespace: ep.SourceNamespace, SourceName: ep.SourceName,
		},
	}
	if err := fakeClient.Create(ctx, cr); err != nil {
		t.Fatalf("failed to create CR: %v", err)
	}
	cr.Status = securityv1alpha1.TLSComplianceReportStatus{
		ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
		CheckCount:       1,
		FirstSeenAt:      &now,
		LastSeenAt:       &now,
	}
	if err := fakeClient.Status().Update(ctx, cr); err != nil {
		t.Fatalf("failed to update CR status: %v", err)
	}

	checkerCallsBefore := checker.CheckCount()
	err := reconciler.processEndpoint(ctx, &ep)
	if err != nil {
		t.Fatalf("processEndpoint() error = %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if checker.CheckCount() != checkerCallsBefore {
		t.Error("TLS checker should not be called for non-Pending CR")
	}
}

func TestProcessEndpoint_PendingRetryWorkersBusy(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     &MockTLSChecker{},
		CertExpiryDays: 30,
		Workers:        1,
		ManagerCtx:     ctx,
	}

	// Fill the semaphore so workers are busy
	reconciler.initCheckSemaphore()
	reconciler.checkSem <- struct{}{}

	ep := endpoint.Endpoint{
		Host:            "busy-retry.example",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "busy-retry-svc",
	}

	crName := endpoint.GenerateCRName(&ep)
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: ep.Host, Port: ep.Port,
			SourceKind: ep.SourceKind, SourceNamespace: ep.SourceNamespace, SourceName: ep.SourceName,
		},
	}
	if err := fakeClient.Create(ctx, cr); err != nil {
		t.Fatalf("failed to create CR: %v", err)
	}
	cr.Status = securityv1alpha1.TLSComplianceReportStatus{
		ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
		CheckCount:       0,
		FirstSeenAt:      &now,
		LastSeenAt:       &now,
	}
	if err := fakeClient.Status().Update(ctx, cr); err != nil {
		t.Fatalf("failed to update CR status: %v", err)
	}

	err := reconciler.processEndpoint(ctx, &ep)
	if !errors.Is(err, errWorkersBusy) {
		t.Errorf("processEndpoint() error = %v, want errWorkersBusy", err)
	}

	// Drain semaphore
	<-reconciler.checkSem
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
		ExcludeNamespaces: map[string]bool{"kube-system": true},
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

func TestEndpointReconciler_CleanupOrphanedCRs_BatchedLookup(t *testing.T) {
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

	// CR whose source pod still exists
	existingCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "existing-pod-cr",
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "10.0.0.1",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindPod,
			SourceNamespace: testNamespace,
			SourceName:      "existing-pod",
		},
	}

	// CR whose source pod was deleted (orphaned)
	orphanedCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "deleted-pod-cr",
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "10.0.0.2",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindPod,
			SourceNamespace: testNamespace,
			SourceName:      "deleted-pod",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod, existingCR, orphanedCR).
		Build()

	reconciler := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	if err := reconciler.cleanupOrphanedCRs(ctx); err != nil {
		t.Fatalf("cleanupOrphanedCRs() error = %v", err)
	}

	// Verify the orphaned CR was deleted and the existing one remains
	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 CR after cleanup, got %d", len(crList.Items))
	}
	if crList.Items[0].Name != "existing-pod-cr" {
		t.Errorf("expected remaining CR to be 'existing-pod-cr', got %q", crList.Items[0].Name)
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

func TestScanPodEndpoints_Paginated(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-page1", Namespace: testNamespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-page2", Namespace: testNamespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.2"},
	}

	callCount := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod1, pod2).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if podList, ok := list.(*corev1.PodList); ok {
					callCount++
					if err := cl.List(ctx, list, opts...); err != nil {
						return err
					}
					if callCount == 1 && len(podList.Items) > 1 {
						podList.Items = podList.Items[:1]
						podList.Continue = "page2-token"
					}
					return nil
				}
				return cl.List(ctx, list, opts...)
			},
		}).
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

	if callCount < 2 {
		t.Errorf("expected at least 2 List calls for pagination, got %d", callCount)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) < 1 {
		t.Error("expected at least 1 TLSComplianceReport from paginated scan")
	}
}

func TestScanPodEndpoints_ListError(t *testing.T) {
	scheme := newTestScheme()
	injectedErr := fmt.Errorf("injected pod list error")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return injectedErr
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	err := reconciler.scanPodEndpoints(context.Background())
	if err == nil {
		t.Fatal("expected error from scanPodEndpoints when List fails")
	}
	if !strings.Contains(err.Error(), "injected pod list error") {
		t.Errorf("expected injected error, got: %v", err)
	}
}

func TestScanPodEndpoints_EmptyList(t *testing.T) {
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

	err := reconciler.scanPodEndpoints(context.Background())
	if err != nil {
		t.Fatalf("scanPodEndpoints() with empty list error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(context.Background(), &crList); err != nil {
		t.Fatalf("Failed to list CRs: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("expected 0 CRs from empty pod list, got %d", len(crList.Items))
	}
}

func TestCleanupOrphanedCRs_PodListError_PreservesCRs(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	podCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-sourced-cr",
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "10.0.0.5",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindPod,
			SourceNamespace: testNamespace,
			SourceName:      "gone-pod",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(podCR).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return fmt.Errorf("injected pod list error")
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	reconciler := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	err := reconciler.cleanupOrphanedCRs(ctx)
	if err != nil {
		t.Fatalf("cleanupOrphanedCRs() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("List CRs error = %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("expected pod-sourced CR to be preserved on List error, got %d CRs", len(crList.Items))
	}
	if crList.Items[0].Name != "pod-sourced-cr" {
		t.Errorf("expected 'pod-sourced-cr' to survive, got %q", crList.Items[0].Name)
	}
}

func TestCleanupOrphanedCRs_PodPagination(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: testNamespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: testNamespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	existingCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-b-cr"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "10.0.0.2",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindPod,
			SourceNamespace: testNamespace,
			SourceName:      "pod-b",
		},
	}
	orphanedCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "deleted-pod-cr"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "10.0.0.99",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindPod,
			SourceNamespace: testNamespace,
			SourceName:      "deleted-pod",
		},
	}

	podListCalls := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod1, pod2, existingCR, orphanedCR).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if podList, ok := list.(*corev1.PodList); ok {
					podListCalls++
					if err := cl.List(ctx, list, opts...); err != nil {
						return err
					}
					if podListCalls == 1 && len(podList.Items) > 1 {
						podList.Items = podList.Items[:1]
						podList.Continue = "page2"
					}
					return nil
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	reconciler := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	if err := reconciler.cleanupOrphanedCRs(ctx); err != nil {
		t.Fatalf("cleanupOrphanedCRs() error = %v", err)
	}

	if podListCalls < 2 {
		t.Errorf("expected at least 2 pod List calls for pagination, got %d", podListCalls)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("List CRs error = %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 CR (orphan deleted, existing kept), got %d", len(crList.Items))
	}
	if crList.Items[0].Name != "pod-b-cr" {
		t.Errorf("expected 'pod-b-cr' to survive cleanup, got %q", crList.Items[0].Name)
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

	reconciler.performTLSCheck(ctx, crName, "test.example.com", 443, "default", false)

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

	reconciler.performTLSCheck(ctx, crName, "unreachable.example.com", 443, "default", false)

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

func TestPerformTLSCheck_ReleasesSemaphoreDuringBackoff(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	crName := "sem-release-test-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "test.example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "test-svc",
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
			{FailureReason: tlscheck.FailureReasonUnreachable},
			{SupportsTLS12: true, SupportsTLS13: true, CipherSuites: map[string][]string{}},
		},
		Errors: []error{
			fmt.Errorf("connection refused"),
			nil,
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   200 * time.Millisecond,
		Workers:        1,
	}
	reconciler.initCheckSemaphore()

	// Acquire the semaphore (simulating processEndpoint's acquire)
	reconciler.checkSem <- struct{}{}

	// Run performTLSCheck in a goroutine (it will fail once, then backoff)
	done := make(chan struct{})
	go func() {
		defer func() { <-reconciler.checkSem }()
		reconciler.performTLSCheck(ctx, crName, "test.example.com", 443, "default", true)
		close(done)
	}()

	// Wait briefly for the first check to fail and backoff to start
	time.Sleep(50 * time.Millisecond)

	// The semaphore should be free during the backoff sleep
	select {
	case reconciler.checkSem <- struct{}{}:
		// Successfully acquired — semaphore was released during backoff
		<-reconciler.checkSem
	case <-time.After(500 * time.Millisecond):
		t.Fatal("semaphore was not released during retry backoff — worker starvation bug")
	}

	<-done
}

func TestPerformTLSCheck_SemaphoreBalancedOnContextCancel(t *testing.T) {
	scheme := newTestScheme()

	crName := "sem-cancel-test-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "cancel.example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "cancel-svc",
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
			{FailureReason: tlscheck.FailureReasonUnreachable},
			{FailureReason: tlscheck.FailureReasonUnreachable},
		},
		Errors: []error{
			fmt.Errorf("connection refused"),
			fmt.Errorf("connection refused"),
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   200 * time.Millisecond,
		Workers:        1,
	}
	reconciler.initCheckSemaphore()

	ctx, cancel := context.WithCancel(context.Background())

	reconciler.checkSem <- struct{}{}

	done := make(chan struct{})
	go func() {
		defer func() {
			<-reconciler.checkSem
			close(done)
		}()
		reconciler.performTLSCheck(ctx, crName, "cancel.example.com", 443, "default", true)
	}()

	// Wait for first check to fail and backoff to begin
	time.Sleep(50 * time.Millisecond)

	// Cancel context during backoff sleep
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("performTLSCheck did not return after context cancellation")
	}

	// Verify semaphore capacity is correct — should have exactly 0 tokens in the channel
	if len(reconciler.checkSem) != 0 {
		t.Errorf("semaphore has %d tokens, want 0 (balanced after cancel)", len(reconciler.checkSem))
	}
	if cap(reconciler.checkSem) != 1 {
		t.Errorf("semaphore capacity is %d, want 1", cap(reconciler.checkSem))
	}
}

func TestPerformTLSCheck_MultiRetrySemaphoreRelease(t *testing.T) {
	scheme := newTestScheme()

	crName := "multi-retry-sem-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "multi.example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "multi-svc",
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
			{FailureReason: tlscheck.FailureReasonUnreachable},
			{FailureReason: tlscheck.FailureReasonUnreachable},
			{SupportsTLS12: true, SupportsTLS13: true, CipherSuites: map[string][]string{}},
		},
		Errors: []error{
			fmt.Errorf("connection refused"),
			fmt.Errorf("connection refused"),
			nil,
		},
	}

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   100 * time.Millisecond,
		Workers:        1,
	}
	reconciler.initCheckSemaphore()

	reconciler.checkSem <- struct{}{}

	done := make(chan struct{})
	go func() {
		defer func() { <-reconciler.checkSem }()
		reconciler.performTLSCheck(context.Background(), crName, "multi.example.com", 443, "default", true)
		close(done)
	}()

	// Probe the semaphore during each backoff window
	for i := range 2 {
		time.Sleep(50 * time.Millisecond)
		select {
		case reconciler.checkSem <- struct{}{}:
			<-reconciler.checkSem
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("semaphore not released during backoff window %d", i+1)
		}
		// Wait for the backoff to finish and next attempt to start
		time.Sleep(150 * time.Millisecond)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("performTLSCheck did not complete")
	}

	if checker.CallCount() != 3 {
		t.Errorf("expected 3 calls, got %d", checker.CallCount())
	}

	if len(reconciler.checkSem) != 0 {
		t.Errorf("semaphore has %d tokens, want 0", len(reconciler.checkSem))
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

	reconciler.performTLSCheck(ctx, crName, "notls.example.com", 80, "default", false)

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

func TestEndpointReconciler_NoRetryOnPlaintextHTTP(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	crName := "no-retry-http-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "http.example.com",
			Port:            80,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "http-service",
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
			{FailureReason: tlscheck.FailureReasonPlaintextHTTP},
		},
		Errors: []error{
			fmt.Errorf("plaintext HTTP"),
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

	reconciler.performTLSCheck(ctx, crName, "http.example.com", 80, "default", false)

	if checker.CallCount() != 1 {
		t.Errorf("expected 1 call (no retry for PlaintextHTTP), got %d", checker.CallCount())
	}

	var updatedCR securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &updatedCR); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}
	if updatedCR.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusPlaintextHTTP {
		t.Errorf("ComplianceStatus = %v, want PlaintextHTTP", updatedCR.Status.ComplianceStatus)
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

	reconciler.performTLSCheck(ctx, crName, "mtls.example.com", 443, "default", false)

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

	reconciler.performTLSCheck(ctx, crName, "timeout.example.com", 443, "default", false)

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

func TestEndpointReconciler_RetryBackoffCap(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	crName := "retry-backoff-cap-cr"
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "slow.example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "slow-service",
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
			{FailureReason: tlscheck.FailureReasonTimeout},
			{FailureReason: tlscheck.FailureReasonTimeout},
			{FailureReason: tlscheck.FailureReasonTimeout},
		},
		Errors: []error{
			fmt.Errorf("timeout 1"),
			fmt.Errorf("timeout 2"),
			fmt.Errorf("timeout 3"),
			fmt.Errorf("timeout 4"),
		},
	}

	// Without cap: backoff would be 10ms, 20ms, 40ms = 70ms total
	// With cap at 15ms: backoff is 10ms, 15ms(+jitter), 15ms(+jitter) ≤ ~60ms
	// Without cap and higher retries the difference would be dramatic
	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   10 * time.Millisecond,
		MaxBackoff:     15 * time.Millisecond,
	}

	start := time.Now()
	reconciler.performTLSCheck(ctx, crName, "slow.example.com", 443, "default", false)
	elapsed := time.Since(start)

	if checker.CallCount() != 4 {
		t.Errorf("expected 4 calls, got %d", checker.CallCount())
	}

	// 3 sleeps, each capped at 15ms + up to 25% jitter ≈ 18.75ms max per sleep
	// Total max ≈ 56.25ms, give generous upper bound of 500ms for CI with -race
	if elapsed > 500*time.Millisecond {
		t.Errorf("elapsed %v exceeds 500ms — backoff cap may not be working", elapsed)
	}
}

func TestPeriodicScan_UpdatesCRStatus(t *testing.T) {
	scheme := newTestScheme()

	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "scan-target-cr",
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "api.example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "api-svc",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
		TLSChecker: &MockTLSChecker{
			Result: &tlscheck.TLSCheckResult{
				SupportsTLS12: true,
				SupportsTLS13: true,
				CipherSuites:  map[string][]string{"TLS 1.3": {"TLS_AES_128_GCM_SHA256"}},
			},
		},
		CertExpiryDays: 30,
		Workers:        1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	elected := make(chan struct{})
	close(elected)
	reconciler.StartPeriodicScan(ctx, 50*time.Millisecond, elected)
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	var updated securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: "scan-target-cr"}, &updated); err != nil {
		t.Fatalf("failed to get CR: %v", err)
	}
	if updated.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusCompliant {
		t.Errorf("ComplianceStatus = %v, want Compliant", updated.Status.ComplianceStatus)
	}
	if !updated.Status.TLSVersions.TLS13 {
		t.Error("expected TLSVersions.TLS13 = true")
	}
}

func TestCleanupLoop_RemovesOrphanedCRs(t *testing.T) {
	scheme := newTestScheme()

	existingSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alive-svc",
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 443}},
		},
	}

	aliveCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "alive-cr"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "alive-svc.default",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "alive-svc",
		},
	}

	orphanedCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "orphaned-cr"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "gone-svc.default",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "gone-svc",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingSvc, aliveCR, orphanedCR).
		Build()

	reconciler := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx, cancel := context.WithCancel(context.Background())
	reconciler.StartCleanupLoop(ctx, 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(context.Background(), &crList); err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 CR after cleanup loop, got %d", len(crList.Items))
	}
	if crList.Items[0].Name != "alive-cr" {
		t.Errorf("expected surviving CR to be 'alive-cr', got %q", crList.Items[0].Name)
	}
}

func TestPeriodicScan_RespectsContextCancellation(t *testing.T) {
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
		TLSChecker: &MockTLSChecker{
			Result: &tlscheck.TLSCheckResult{SupportsTLS13: true},
		},
		CertExpiryDays: 30,
	}

	ctx, cancel := context.WithCancel(context.Background())
	elected := make(chan struct{})
	close(elected)
	reconciler.StartPeriodicScan(ctx, 1*time.Hour, elected)
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestEndpointReconciler_HandleGatewayResource_HTTPRoute(t *testing.T) {
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

	httpRoute := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]interface{}{"name": "test-route", "namespace": "default"},
		"spec":       map[string]interface{}{"hostnames": []interface{}{"app.example.com", "api.example.com"}},
	}}

	gvk := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	_, err := reconciler.handleGatewayResource(ctx, httpRoute, gvk)
	if err != nil {
		t.Fatalf("handleGatewayResource() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 2 {
		t.Fatalf("expected 2 reports (one per hostname), got %d", len(crList.Items))
	}
	for _, cr := range crList.Items {
		if cr.Spec.SourceKind != securityv1alpha1.SourceKindHTTPRoute {
			t.Errorf("sourceKind = %q, want HTTPRoute", cr.Spec.SourceKind)
		}
		if cr.Spec.SourceName != "test-route" {
			t.Errorf("sourceName = %q, want test-route", cr.Spec.SourceName)
		}
	}
}

func TestEndpointReconciler_HandleGatewayResource_Gateway(t *testing.T) {
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

	gateway := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata":   map[string]interface{}{"name": "my-gw", "namespace": "default"},
		"spec": map[string]interface{}{
			"listeners": []interface{}{
				map[string]interface{}{"protocol": "HTTPS", "port": int64(443)},
				map[string]interface{}{"protocol": "HTTP", "port": int64(80)},
			},
		},
	}}

	gvk := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway"}
	_, err := reconciler.handleGatewayResource(ctx, gateway, gvk)
	if err != nil {
		t.Fatalf("handleGatewayResource() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 report (HTTPS only, HTTP skipped), got %d", len(crList.Items))
	}
	if crList.Items[0].Spec.SourceKind != securityv1alpha1.SourceKindGateway {
		t.Errorf("sourceKind = %q, want Gateway", crList.Items[0].Spec.SourceKind)
	}
	if crList.Items[0].Spec.Port != 443 {
		t.Errorf("port = %d, want 443", crList.Items[0].Spec.Port)
	}
}

func TestEndpointReconciler_HandleGatewayResource_EmptyHTTPRoute(t *testing.T) {
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

	httpRoute := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]interface{}{"name": "empty-route", "namespace": "default"},
		"spec":       map[string]interface{}{},
	}}

	gvk := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	_, err := reconciler.handleGatewayResource(ctx, httpRoute, gvk)
	if err != nil {
		t.Fatalf("handleGatewayResource() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("expected 0 reports for empty HTTPRoute, got %d", len(crList.Items))
	}
}

func TestUpdateConditions_PQCCompliant_FIPSEnabled(t *testing.T) {
	r := &EndpointReconciler{FIPSEnabled: true}
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable
	result := &tlscheck.TLSCheckResult{
		SupportsTLS13: true,
	}

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, result)

	for _, c := range cr.Status.Conditions {
		if c.Type == "PQCCompliant" {
			if c.Status != metav1.ConditionFalse {
				t.Errorf("expected PQCCompliant status False, got %s", c.Status)
			}
			if c.Reason != "TLS13Capable" {
				t.Errorf("expected reason TLS13Capable, got %s", c.Reason)
			}
			expected := "Endpoint supports TLS 1.3 but has not negotiated a post-quantum key exchange (FIPS mode active, ML-KEM unavailable)"
			if c.Message != expected {
				t.Errorf("expected FIPS-aware message %q, got %q", expected, c.Message)
			}
			return
		}
	}
	t.Error("PQCCompliant condition not found")
}

func TestUpdateConditions_PQCCompliant_FIPSDisabled(t *testing.T) {
	r := &EndpointReconciler{FIPSEnabled: false}
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable
	result := &tlscheck.TLSCheckResult{
		SupportsTLS13: true,
	}

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, result)

	for _, c := range cr.Status.Conditions {
		if c.Type == "PQCCompliant" {
			expected := "Endpoint supports TLS 1.3 but has not negotiated a post-quantum key exchange"
			if c.Message != expected {
				t.Errorf("expected non-FIPS message %q, got %q", expected, c.Message)
			}
			return
		}
	}
	t.Error("PQCCompliant condition not found")
}

func TestUpdateConditions_PQCCompliant_FIPSEnabled_PQCReady(t *testing.T) {
	r := &EndpointReconciler{FIPSEnabled: true}
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Status.PQCReadiness = securityv1alpha1.PQCReadinessPQCReady
	result := &tlscheck.TLSCheckResult{
		SupportsTLS13:    true,
		MLKEMSupported:   true,
		NegotiatedCurves: map[string]string{"TLS 1.3": "X25519MLKEM768"},
	}

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, result)

	for _, c := range cr.Status.Conditions {
		if c.Type == "PQCCompliant" {
			if c.Status != metav1.ConditionTrue {
				t.Errorf("expected PQCCompliant status True, got %s", c.Status)
			}
			return
		}
	}
	t.Error("PQCCompliant condition not found")
}

func TestUpdateConditions_PQCCompliant_FIPSEnabled_LegacyTLS(t *testing.T) {
	r := &EndpointReconciler{FIPSEnabled: true}
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Status.PQCReadiness = securityv1alpha1.PQCReadinessLegacyTLS
	result := &tlscheck.TLSCheckResult{
		SupportsTLS12: true,
	}

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, result)

	for _, c := range cr.Status.Conditions {
		if c.Type == "PQCCompliant" {
			if strings.Contains(c.Message, "FIPS") {
				t.Errorf("FIPS should not appear in LegacyTLS condition message, got %q", c.Message)
			}
			expected := "Endpoint only supports TLS 1.2 or older, no path to post-quantum cryptography"
			if c.Message != expected {
				t.Errorf("expected message %q, got %q", expected, c.Message)
			}
			return
		}
	}
	t.Error("PQCCompliant condition not found")
}

func drainEvents(recorder *events.FakeRecorder) []string {
	var events []string
	for {
		select {
		case e := <-recorder.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}

func TestEmitComplianceEvents_PQCNotReady_FIPSEnabled(t *testing.T) {
	recorder := events.NewFakeRecorder(10)
	r := &EndpointReconciler{FIPSEnabled: true, Recorder: recorder}
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Spec.Host = "example.com"
	cr.Spec.Port = 443
	cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	cr.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable

	r.emitComplianceEvents(cr,
		securityv1alpha1.ComplianceStatusCompliant,
		securityv1alpha1.PQCReadinessPQCReady,
		&tlscheck.TLSCheckResult{SupportsTLS13: true})

	events := drainEvents(recorder)
	found := false
	for _, event := range events {
		if strings.Contains(event, EventReasonPQCNotReady) {
			found = true
			if !strings.Contains(event, "FIPS mode active, ML-KEM unavailable") {
				t.Errorf("expected FIPS suffix in PQCNotReady event, got %q", event)
			}
		}
	}
	if !found {
		t.Error("expected a PQCNotReady event to be emitted")
	}
}

func TestEmitComplianceEvents_PQCNotReady_FIPSDisabled(t *testing.T) {
	recorder := events.NewFakeRecorder(10)
	r := &EndpointReconciler{FIPSEnabled: false, Recorder: recorder}
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Spec.Host = "example.com"
	cr.Spec.Port = 443
	cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	cr.Status.PQCReadiness = securityv1alpha1.PQCReadinessTLS13Capable

	r.emitComplianceEvents(cr,
		securityv1alpha1.ComplianceStatusCompliant,
		securityv1alpha1.PQCReadinessPQCReady,
		&tlscheck.TLSCheckResult{SupportsTLS13: true})

	events := drainEvents(recorder)
	for _, event := range events {
		if strings.Contains(event, EventReasonPQCNotReady) && strings.Contains(event, "FIPS") {
			t.Errorf("expected no FIPS suffix in PQCNotReady event, got %q", event)
		}
	}
}

func TestEmitComplianceEvents_PQCNotReady_FIPSEnabled_LegacyTLS(t *testing.T) {
	recorder := events.NewFakeRecorder(10)
	r := &EndpointReconciler{FIPSEnabled: true, Recorder: recorder}
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Spec.Host = "example.com"
	cr.Spec.Port = 443
	cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	cr.Status.PQCReadiness = securityv1alpha1.PQCReadinessLegacyTLS

	r.emitComplianceEvents(cr,
		securityv1alpha1.ComplianceStatusCompliant,
		securityv1alpha1.PQCReadinessPQCReady,
		&tlscheck.TLSCheckResult{SupportsTLS12: true})

	events := drainEvents(recorder)
	for _, event := range events {
		if strings.Contains(event, EventReasonPQCNotReady) && strings.Contains(event, "FIPS") {
			t.Errorf("FIPS suffix should not appear for LegacyTLS, got %q", event)
		}
	}
}

func TestStartPeriodicScan_WaitsForElection(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	elected := make(chan struct{})
	r.StartPeriodicScan(ctx, time.Hour, elected)

	// InitialScanDone should still be false — election hasn't fired
	time.Sleep(50 * time.Millisecond)
	if r.InitialScanDone.Load() {
		t.Fatal("InitialScanDone should be false before leader election")
	}

	// Fire the election
	close(elected)
	time.Sleep(100 * time.Millisecond)

	if !r.InitialScanDone.Load() {
		t.Fatal("InitialScanDone should be true after leader election")
	}
}

func TestStartPeriodicScan_NilElectedChannel(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.StartPeriodicScan(ctx, time.Hour, nil)
	time.Sleep(100 * time.Millisecond)

	if !r.InitialScanDone.Load() {
		t.Fatal("InitialScanDone should be true immediately with nil elected channel")
	}
}

func TestStartPeriodicScan_ContextCancelledBeforeElection(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	elected := make(chan struct{})

	r.StartPeriodicScan(ctx, time.Hour, elected)

	// Cancel before election fires
	time.Sleep(20 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	if r.InitialScanDone.Load() {
		t.Fatal("InitialScanDone should be false when context cancelled before election")
	}
}

func TestStartPeriodicScan_RunOnce(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		TLSChecker:  &MockTLSChecker{},
		RunOnce:     true,
		RunOnceDone: make(chan error, 1),
		Workers:     1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	elected := make(chan struct{})
	close(elected)
	r.StartPeriodicScan(ctx, time.Hour, elected)

	select {
	case err := <-r.RunOnceDone:
		if err != nil {
			t.Logf("scan returned error (expected in test without real endpoints): %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for RunOnceDone signal")
	}

	if !r.InitialScanDone.Load() {
		t.Error("InitialScanDone should be true after StartPeriodicScan completes")
	}
}

func TestScanAllEndpoints_PropagatesPodScanError(t *testing.T) {
	scheme := newTestScheme()
	injectedErr := fmt.Errorf("injected pod list error")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return injectedErr
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	err := r.scanAllEndpoints(context.Background())
	if err == nil {
		t.Fatal("expected scanAllEndpoints to return an error when pod scan fails")
	}
	if !strings.Contains(err.Error(), "injected pod list error") {
		t.Errorf("expected injected error, got: %v", err)
	}
}

func TestEnsureOwnerReference_AddsNewOwnerRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-report",
		},
	}

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-target",
			UID:  "target-uid-123",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(report).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	err := r.ensureOwnerReference(context.Background(), "test-report", target)
	if err != nil {
		t.Fatalf("ensureOwnerReference returned unexpected error: %v", err)
	}

	var updated securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &updated); err != nil {
		t.Fatalf("failed to get updated report: %v", err)
	}

	if len(updated.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference, got %d", len(updated.OwnerReferences))
	}

	ref := updated.OwnerReferences[0]
	if ref.Name != "test-target" {
		t.Errorf("expected owner name 'test-target', got %q", ref.Name)
	}
	if ref.UID != "target-uid-123" {
		t.Errorf("expected owner UID 'target-uid-123', got %q", ref.UID)
	}
	if ref.Kind != "TLSComplianceTarget" {
		t.Errorf("expected owner kind 'TLSComplianceTarget', got %q", ref.Kind)
	}
	if ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Error("expected BlockOwnerDeletion to be true")
	}
}

func TestEnsureOwnerReference_AlreadyHasOwner(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	blockDeletion := true
	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-report",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         securityv1alpha1.GroupVersion.String(),
					Kind:               "TLSComplianceTarget",
					Name:               "test-target",
					UID:                "target-uid-123",
					BlockOwnerDeletion: &blockDeletion,
				},
			},
		},
	}

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-target",
			UID:  "target-uid-123",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(report).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	err := r.ensureOwnerReference(context.Background(), "test-report", target)
	if err != nil {
		t.Fatalf("ensureOwnerReference returned unexpected error: %v", err)
	}

	var updated securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &updated); err != nil {
		t.Fatalf("failed to get updated report: %v", err)
	}

	if len(updated.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference (no duplicate), got %d", len(updated.OwnerReferences))
	}
}

func TestEnsureOwnerReference_ReportNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-target",
			UID:  "target-uid-123",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	err := r.ensureOwnerReference(context.Background(), "nonexistent-report", target)
	if err == nil {
		t.Fatal("expected error when report does not exist")
	}
}

func TestHandleTarget_SetsOwnerReference(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-target",
			UID:  "target-uid-456",
		},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "example.com",
			Port: 443,
		},
	}

	ep := endpoint.Endpoint{
		Host:            "example.com",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindTarget,
		SourceNamespace: "cluster-scoped",
		SourceName:      "test-target",
	}
	reportName := endpoint.GenerateCRName(&ep)

	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: reportName,
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "example.com",
			Port: 443,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}, &securityv1alpha1.TLSComplianceTarget{}).
		WithObjects(target, report).
		Build()

	r := &EndpointReconciler{
		Client:  fakeClient,
		Scheme:  scheme,
		Workers: 1,
		TLSChecker: &MockTLSChecker{
			Result: &tlscheck.TLSCheckResult{
				SupportsTLS13: true,
			},
		},
		Recorder: events.NewFakeRecorder(10),
	}

	_, err := r.handleTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("handleTarget returned unexpected error: %v", err)
	}

	var updated securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: reportName}, &updated); err != nil {
		t.Fatalf("failed to get updated report: %v", err)
	}

	if len(updated.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference, got %d", len(updated.OwnerReferences))
	}

	ref := updated.OwnerReferences[0]
	if ref.UID != "target-uid-456" {
		t.Errorf("expected owner UID 'target-uid-456', got %q", ref.UID)
	}
}

func TestHandleEndpoints_ReturnsFirstProcessEndpointError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*securityv1alpha1.TLSComplianceReport); ok {
					return fmt.Errorf("injected create error")
				}
				return client.Create(ctx, obj, opts...)
			},
		}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		Workers:    1,
		TLSChecker: &MockTLSChecker{},
		Recorder:   events.NewFakeRecorder(10),
	}

	endpoints := []endpoint.Endpoint{
		{Host: "svc.ns", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "svc"},
	}

	_, err := r.handleEndpoints(context.Background(), endpoints, securityv1alpha1.SourceKindService)
	if err == nil {
		t.Fatal("expected error from handleEndpoints when processEndpoint fails")
	}
}

func TestHandleEndpoints_SuccessReturnsNil(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:  fakeClient,
		Scheme:  scheme,
		Workers: 1,
		TLSChecker: &MockTLSChecker{
			Result: &tlscheck.TLSCheckResult{SupportsTLS13: true},
		},
		Recorder: events.NewFakeRecorder(10),
	}

	endpoints := []endpoint.Endpoint{
		{Host: "svc.ns", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "svc"},
	}

	_, err := r.handleEndpoints(context.Background(), endpoints, securityv1alpha1.SourceKindService)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestHandleHeadlessService_EndpointSliceListError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = discoveryv1.AddToScheme(scheme)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Ports:     []corev1.ServicePort{{Port: 443, Name: "https"}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		WithObjects(svc).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*discoveryv1.EndpointSliceList); ok {
					return fmt.Errorf("injected list error")
				}
				return client.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		Workers:    1,
		TLSChecker: &MockTLSChecker{},
		Recorder:   events.NewFakeRecorder(10),
	}

	_, err := r.handleHeadlessService(context.Background(), svc)
	if err == nil {
		t.Fatal("expected error when EndpointSlice list fails")
	}
}

func TestHandleTarget_ProcessEndpointError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "fail-target", UID: "uid-123"},
		Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "fail.example.com", Port: 443},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}, &securityv1alpha1.TLSComplianceTarget{}).
		WithObjects(target).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*securityv1alpha1.TLSComplianceReport); ok {
					return fmt.Errorf("injected create error")
				}
				return client.Create(ctx, obj, opts...)
			},
		}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		Workers:    1,
		TLSChecker: &MockTLSChecker{},
		Recorder:   events.NewFakeRecorder(10),
	}

	_, err := r.handleTarget(context.Background(), target)
	if err == nil {
		t.Fatal("expected error from handleTarget when processEndpoint fails")
	}
}

func TestHandleEndpoints_WorkersBusy_Requeues(t *testing.T) {
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		Workers:    1,
		TLSChecker: &MockTLSChecker{},
		Recorder:   events.NewFakeRecorder(10),
		ManagerCtx: context.Background(),
	}

	r.initCheckSemaphore()
	// Fill the semaphore so all workers appear busy
	r.checkSem <- struct{}{}

	endpoints := []endpoint.Endpoint{
		{
			Host:            "test-svc.default",
			Port:            8443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "test-svc",
		},
	}

	result, err := r.handleEndpoints(context.Background(), endpoints, securityv1alpha1.SourceKindService)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.RequeueAfter != workerBusyRequeueDelay {
		t.Errorf("expected RequeueAfter=%v, got %v", workerBusyRequeueDelay, result.RequeueAfter)
	}

	// Drain the semaphore
	<-r.checkSem
}

func TestHandleTarget_WorkersBusy_Requeues(t *testing.T) {
	scheme := newTestScheme()

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "busy-target"},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "busy-host.example.com",
			Port: 443,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(target).
		WithStatusSubresource(target, &securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		Workers:    1,
		TLSChecker: &MockTLSChecker{},
		Recorder:   events.NewFakeRecorder(10),
		ManagerCtx: context.Background(),
	}

	r.initCheckSemaphore()
	r.checkSem <- struct{}{}

	result, err := r.handleTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected no error from handleTarget when workers busy, got %v", err)
	}
	if result.RequeueAfter != workerBusyRequeueDelay {
		t.Errorf("expected RequeueAfter=%v, got %v", workerBusyRequeueDelay, result.RequeueAfter)
	}

	<-r.checkSem
}

func TestParseNamespaceList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string]bool{},
		},
		{
			name:     "single namespace",
			input:    "default",
			expected: map[string]bool{"default": true},
		},
		{
			name:     "multiple namespaces",
			input:    "default,kube-system,monitoring",
			expected: map[string]bool{"default": true, "kube-system": true, "monitoring": true},
		},
		{
			name:     "whitespace trimming",
			input:    " default , kube-system , monitoring ",
			expected: map[string]bool{"default": true, "kube-system": true, "monitoring": true},
		},
		{
			name:     "trailing comma produces empty segment skipped",
			input:    "default,kube-system,",
			expected: map[string]bool{"default": true, "kube-system": true},
		},
		{
			name:     "only commas",
			input:    ",,,",
			expected: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseNamespaceList(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d entries, got %d: %v", len(tt.expected), len(result), result)
				return
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected key %q=%v, got %v", k, v, result[k])
				}
			}
		})
	}
}

func TestFailureReasonToComplianceStatus(t *testing.T) {
	tests := []struct {
		reason   tlscheck.FailureReason
		expected securityv1alpha1.ComplianceStatus
	}{
		{tlscheck.FailureReasonNoTLS, securityv1alpha1.ComplianceStatusNoTLS},
		{tlscheck.FailureReasonPlaintextHTTP, securityv1alpha1.ComplianceStatusPlaintextHTTP},
		{tlscheck.FailureReasonMutualTLSRequired, securityv1alpha1.ComplianceStatusMutualTLSRequired},
		{tlscheck.FailureReasonTimeout, securityv1alpha1.ComplianceStatusTimeout},
		{tlscheck.FailureReasonClosed, securityv1alpha1.ComplianceStatusClosed},
		{tlscheck.FailureReasonFiltered, securityv1alpha1.ComplianceStatusFiltered},
		{tlscheck.FailureReasonUnreachable, securityv1alpha1.ComplianceStatusUnreachable},
		{tlscheck.FailureReason("SomethingUnknown"), securityv1alpha1.ComplianceStatusUnreachable},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			got := failureReasonToComplianceStatus(tt.reason)
			if got != tt.expected {
				t.Errorf("failureReasonToComplianceStatus(%q) = %q, want %q", tt.reason, got, tt.expected)
			}
		})
	}
}

func TestHostPort(t *testing.T) {
	tests := []struct {
		host     string
		port     int32
		expected string
	}{
		{"192.168.1.1", 443, "192.168.1.1:443"},
		{"example.com", 8443, "example.com:8443"},
		{"::1", 443, "[::1]:443"},
		{"fe80::1", 8080, "[fe80::1]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := hostPort(tt.host, tt.port)
			if got != tt.expected {
				t.Errorf("hostPort(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.expected)
			}
		})
	}
}

func TestUpdateConditions_TLSCompliant(t *testing.T) {
	tests := []struct {
		name           string
		status         securityv1alpha1.ComplianceStatus
		expectedStatus metav1.ConditionStatus
		expectedReason string
	}{
		{
			name:           "Compliant",
			status:         securityv1alpha1.ComplianceStatusCompliant,
			expectedStatus: metav1.ConditionTrue,
			expectedReason: "Compliant",
		},
		{
			name:           "NonCompliant",
			status:         securityv1alpha1.ComplianceStatusNonCompliant,
			expectedStatus: metav1.ConditionFalse,
			expectedReason: "NonCompliant",
		},
		{
			name:           "Warning",
			status:         securityv1alpha1.ComplianceStatusWarning,
			expectedStatus: metav1.ConditionTrue,
			expectedReason: "Warning",
		},
		{
			name:           "Unknown status",
			status:         securityv1alpha1.ComplianceStatusUnreachable,
			expectedStatus: metav1.ConditionUnknown,
			expectedReason: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &EndpointReconciler{}
			cr := &securityv1alpha1.TLSComplianceReport{}
			result := &tlscheck.TLSCheckResult{}

			r.updateConditions(cr, tt.status, result)

			var found bool
			for _, c := range cr.Status.Conditions {
				if c.Type == "TLSCompliant" {
					found = true
					if c.Status != tt.expectedStatus {
						t.Errorf("TLSCompliant status = %v, want %v", c.Status, tt.expectedStatus)
					}
					if c.Reason != tt.expectedReason {
						t.Errorf("TLSCompliant reason = %q, want %q", c.Reason, tt.expectedReason)
					}
				}
			}
			if !found {
				t.Error("TLSCompliant condition not found")
			}
		})
	}
}

func TestUpdateConditions_CertificateValid(t *testing.T) {
	tests := []struct {
		name           string
		cert           *tlscheck.CertificateDetails
		certExpiryDays int
		expectedStatus metav1.ConditionStatus
		expectedReason string
	}{
		{
			name:           "expired certificate",
			cert:           &tlscheck.CertificateDetails{IsExpired: true, DaysUntilExpiry: -5},
			certExpiryDays: 30,
			expectedStatus: metav1.ConditionFalse,
			expectedReason: "Expired",
		},
		{
			name:           "expiring soon",
			cert:           &tlscheck.CertificateDetails{IsExpired: false, DaysUntilExpiry: 15},
			certExpiryDays: 30,
			expectedStatus: metav1.ConditionFalse,
			expectedReason: "Expiring",
		},
		{
			name:           "valid certificate",
			cert:           &tlscheck.CertificateDetails{IsExpired: false, DaysUntilExpiry: 365},
			certExpiryDays: 30,
			expectedStatus: metav1.ConditionTrue,
			expectedReason: "Valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &EndpointReconciler{CertExpiryDays: tt.certExpiryDays}
			cr := &securityv1alpha1.TLSComplianceReport{}
			result := &tlscheck.TLSCheckResult{Certificate: tt.cert}

			r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, result)

			var found bool
			for _, c := range cr.Status.Conditions {
				if c.Type == "CertificateValid" {
					found = true
					if c.Status != tt.expectedStatus {
						t.Errorf("CertificateValid status = %v, want %v", c.Status, tt.expectedStatus)
					}
					if c.Reason != tt.expectedReason {
						t.Errorf("CertificateValid reason = %q, want %q", c.Reason, tt.expectedReason)
					}
				}
			}
			if !found {
				t.Error("CertificateValid condition not found")
			}
		})
	}
}

func TestUpdateConditions_NoCertificate(t *testing.T) {
	r := &EndpointReconciler{}
	cr := &securityv1alpha1.TLSComplianceReport{}
	result := &tlscheck.TLSCheckResult{}

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, result)

	for _, c := range cr.Status.Conditions {
		if c.Type == "CertificateValid" {
			t.Error("CertificateValid condition should not be set when no certificate")
		}
	}
}

func TestUpdateConditions_PQCNoPQC(t *testing.T) {
	r := &EndpointReconciler{}
	cr := &securityv1alpha1.TLSComplianceReport{
		Status: securityv1alpha1.TLSComplianceReportStatus{
			PQCReadiness: securityv1alpha1.PQCReadinessNoPQC,
		},
	}
	result := &tlscheck.TLSCheckResult{}

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, result)

	for _, c := range cr.Status.Conditions {
		if c.Type == "PQCCompliant" {
			if c.Status != metav1.ConditionUnknown {
				t.Errorf("PQCCompliant status = %v, want Unknown", c.Status)
			}
			if c.Reason != "NoPQC" {
				t.Errorf("PQCCompliant reason = %q, want NoPQC", c.Reason)
			}
			return
		}
	}
	t.Error("PQCCompliant condition not found")
}

func TestEmitComplianceEvents(t *testing.T) {
	tests := []struct {
		name             string
		certExpiryDays   int
		complianceStatus securityv1alpha1.ComplianceStatus
		pqcReadiness     securityv1alpha1.PQCReadiness
		oldStatus        securityv1alpha1.ComplianceStatus
		oldPQC           securityv1alpha1.PQCReadiness
		result           *tlscheck.TLSCheckResult
		expectedReason   string
	}{
		{
			name:             "Warning",
			complianceStatus: securityv1alpha1.ComplianceStatusWarning,
			result:           &tlscheck.TLSCheckResult{},
			expectedReason:   EventReasonTLSWarning,
		},
		{
			name:             "NonCompliant",
			complianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
			result:           &tlscheck.TLSCheckResult{},
			expectedReason:   EventReasonTLSNonCompliant,
		},
		{
			name:             "ComplianceChanged",
			complianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			oldStatus:        securityv1alpha1.ComplianceStatusNonCompliant,
			result:           &tlscheck.TLSCheckResult{},
			expectedReason:   EventReasonComplianceChanged,
		},
		{
			name:             "PQCReady",
			complianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			pqcReadiness:     securityv1alpha1.PQCReadinessPQCReady,
			oldPQC:           securityv1alpha1.PQCReadinessTLS13Capable,
			result:           &tlscheck.TLSCheckResult{},
			expectedReason:   EventReasonPQCReady,
		},
		{
			name:             "CertificateExpired",
			complianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			result:           &tlscheck.TLSCheckResult{Certificate: &tlscheck.CertificateDetails{IsExpired: true}},
			expectedReason:   EventReasonCertificateExpired,
		},
		{
			name:             "CertificateExpiring",
			certExpiryDays:   30,
			complianceStatus: securityv1alpha1.ComplianceStatusCompliant,
			result:           &tlscheck.TLSCheckResult{Certificate: &tlscheck.CertificateDetails{IsExpired: false, DaysUntilExpiry: 10}},
			expectedReason:   EventReasonCertificateExpiring,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := events.NewFakeRecorder(10)
			r := &EndpointReconciler{Recorder: recorder, CertExpiryDays: tt.certExpiryDays}
			cr := &securityv1alpha1.TLSComplianceReport{
				Spec: securityv1alpha1.TLSComplianceReportSpec{Host: "example.com", Port: 443},
				Status: securityv1alpha1.TLSComplianceReportStatus{
					ComplianceStatus: tt.complianceStatus,
					PQCReadiness:     tt.pqcReadiness,
				},
			}

			r.emitComplianceEvents(cr, tt.oldStatus, tt.oldPQC, tt.result)

			select {
			case event := <-recorder.Events:
				if !strings.Contains(event, tt.expectedReason) {
					t.Errorf("expected event with reason %q, got %q", tt.expectedReason, event)
				}
			default:
				t.Errorf("expected %s event, got none", tt.expectedReason)
			}
		})
	}
}

func TestEmitComplianceEvents_RecorderNil(t *testing.T) {
	r := &EndpointReconciler{Recorder: nil}
	cr := &securityv1alpha1.TLSComplianceReport{
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusNonCompliant,
		},
	}

	r.emitComplianceEvents(cr, "", "", &tlscheck.TLSCheckResult{})
}

func TestCleanupOrphanedCRs_TTL(t *testing.T) {
	tests := []struct {
		name              string
		retentionDays     int
		lastCheckAt       *metav1.Time
		creationTimestamp metav1.Time
		expectedCRCount   int
	}{
		{
			name:            "expired with LastCheckAt",
			retentionDays:   1,
			lastCheckAt:     func() *metav1.Time { t := metav1.NewTime(time.Now().Add(-48 * time.Hour)); return &t }(),
			expectedCRCount: 0,
		},
		{
			name:            "not expired",
			retentionDays:   1,
			lastCheckAt:     func() *metav1.Time { t := metav1.NewTime(time.Now().Add(-1 * time.Hour)); return &t }(),
			expectedCRCount: 1,
		},
		{
			name:              "nil LastCheckAt uses CreationTimestamp",
			retentionDays:     1,
			creationTimestamp: metav1.NewTime(time.Now().Add(-72 * time.Hour)),
			expectedCRCount:   0,
		},
		{
			name:            "disabled when RetentionDays is 0",
			retentionDays:   0,
			lastCheckAt:     func() *metav1.Time { t := metav1.NewTime(time.Now().Add(-72 * time.Hour)); return &t }(),
			expectedCRCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestScheme()
			ctx := context.Background()

			cr := &securityv1alpha1.TLSComplianceReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-service-443-abc12345",
					Namespace:         testNamespace,
					CreationTimestamp: tt.creationTimestamp,
				},
				Spec: securityv1alpha1.TLSComplianceReportSpec{
					Host:            "test-service.default.svc",
					Port:            443,
					SourceKind:      securityv1alpha1.SourceKindService,
					SourceName:      "test-service",
					SourceNamespace: testNamespace,
				},
				Status: securityv1alpha1.TLSComplianceReportStatus{
					LastCheckAt: tt.lastCheckAt,
				},
			}

			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: testNamespace,
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(cr, svc).
				WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
				Build()

			r := &EndpointReconciler{
				Client:              fakeClient,
				Scheme:              scheme,
				ReportRetentionDays: tt.retentionDays,
			}

			if err := r.cleanupOrphanedCRs(ctx); err != nil {
				t.Fatalf("cleanupOrphanedCRs() error = %v", err)
			}

			var crList securityv1alpha1.TLSComplianceReportList
			if err := fakeClient.List(ctx, &crList); err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if len(crList.Items) != tt.expectedCRCount {
				t.Errorf("expected %d CRs, got %d", tt.expectedCRCount, len(crList.Items))
			}
		})
	}
}

func TestCleanupOrphanedCRs_EmptyList(t *testing.T) {
	scheme := newTestScheme()
	ctx := context.Background()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	if err := r.cleanupOrphanedCRs(ctx); err != nil {
		t.Fatalf("cleanupOrphanedCRs() with empty list error = %v", err)
	}
}

func TestInitCheckSemaphore_DefaultWorkers(t *testing.T) {
	r := &EndpointReconciler{Workers: 0}
	r.initCheckSemaphore()

	if cap(r.checkSem) != 5 {
		t.Errorf("expected default semaphore capacity of 5, got %d", cap(r.checkSem))
	}
}

func TestInitCheckSemaphore_OnceSemantics(t *testing.T) {
	r := &EndpointReconciler{Workers: 3}
	r.initCheckSemaphore()
	r.Workers = 10
	r.initCheckSemaphore()

	if cap(r.checkSem) != 3 {
		t.Errorf("expected semaphore capacity to stay at 3 (sync.Once), got %d", cap(r.checkSem))
	}
}

func TestDetermineComplianceStatus_SSL30Only(t *testing.T) {
	result := &tlscheck.TLSCheckResult{SupportsSSL30: true}
	got := determineComplianceStatus(result)
	if got != securityv1alpha1.ComplianceStatusNonCompliant {
		t.Errorf("SSL 3.0 only = %q, want NonCompliant", got)
	}
}

func TestInitialScanDone(t *testing.T) {
	r := &EndpointReconciler{}

	if r.InitialScanDone.Load() {
		t.Error("InitialScanDone should be false by default")
	}

	r.InitialScanDone.Store(true)

	if !r.InitialScanDone.Load() {
		t.Error("InitialScanDone should be true after Store(true)")
	}
}

func TestUpdateEndpointMetrics(t *testing.T) {
	r := &EndpointReconciler{}

	statusCounts := map[string]float64{
		string(securityv1alpha1.ComplianceStatusCompliant):         3,
		string(securityv1alpha1.ComplianceStatusNonCompliant):      1,
		string(securityv1alpha1.ComplianceStatusWarning):           0,
		string(securityv1alpha1.ComplianceStatusUnreachable):       0,
		string(securityv1alpha1.ComplianceStatusTimeout):           0,
		string(securityv1alpha1.ComplianceStatusClosed):            0,
		string(securityv1alpha1.ComplianceStatusFiltered):          0,
		string(securityv1alpha1.ComplianceStatusNoTLS):             2,
		string(securityv1alpha1.ComplianceStatusPlaintextHTTP):     0,
		string(securityv1alpha1.ComplianceStatusMutualTLSRequired): 0,
		string(securityv1alpha1.ComplianceStatusPending):           0,
		string(securityv1alpha1.ComplianceStatusUnknown):           0,
	}

	r.updateEndpointMetrics(statusCounts)

	g, _ := metrics.EndpointsTotal.GetMetricWithLabelValues(string(securityv1alpha1.ComplianceStatusCompliant))
	m := &dto.Metric{}
	_ = g.Write(m)
	if v := m.GetGauge().GetValue(); v != 3 {
		t.Errorf("expected Compliant=3, got %v", v)
	}

	g, _ = metrics.EndpointsTotal.GetMetricWithLabelValues(string(securityv1alpha1.ComplianceStatusNoTLS))
	m = &dto.Metric{}
	_ = g.Write(m)
	if v := m.GetGauge().GetValue(); v != 2 {
		t.Errorf("expected NoTLS=2, got %v", v)
	}

	g, _ = metrics.EndpointsTotal.GetMetricWithLabelValues(string(securityv1alpha1.ComplianceStatusWarning))
	m = &dto.Metric{}
	_ = g.Write(m)
	if v := m.GetGauge().GetValue(); v != 0 {
		t.Errorf("expected Warning=0, got %v", v)
	}
}

func TestScanAllEndpoints_SortPendingFirst(t *testing.T) {
	scheme := newTestScheme()
	ctx := context.Background()

	now := metav1.Now()
	crs := []client.Object{
		&securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: "compliant-443-aaa11111"},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host: "compliant.default", Port: 443,
				SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: testNamespace, SourceName: "compliant",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				CheckCount:       5,
				FirstSeenAt:      &now,
			},
		},
		&securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: "pending-443-bbb22222"},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host: "pending.default", Port: 443,
				SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: testNamespace, SourceName: "pending",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
				CheckCount:       0,
				FirstSeenAt:      &now,
			},
		},
		&securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: "nontls-443-ccc33333"},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host: "nontls.default", Port: 443,
				SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: testNamespace, SourceName: "nontls",
			},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusNoTLS,
				CheckCount:       3,
				FirstSeenAt:      &now,
			},
		},
	}

	var checkOrder []string
	var mu sync.Mutex
	checker := &OrderTrackingChecker{
		result: &tlscheck.TLSCheckResult{
			SupportsTLS12: true,
			SupportsTLS13: true,
		},
		order: &checkOrder,
		mu:    &mu,
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crs...).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: checker,
		Workers:    1,
	}

	if err := r.scanAllEndpoints(ctx); err != nil {
		t.Fatalf("scanAllEndpoints() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(checkOrder) < 3 {
		t.Fatalf("expected at least 3 checks, got %d: %v", len(checkOrder), checkOrder)
	}

	if checkOrder[0] != "pending.default" {
		t.Errorf("expected pending item to be checked first, got %s", checkOrder[0])
	}
}

type OrderTrackingChecker struct {
	result *tlscheck.TLSCheckResult
	order  *[]string
	mu     *sync.Mutex
}

func (c *OrderTrackingChecker) CheckEndpoint(_ context.Context, host string, _ int) (*tlscheck.TLSCheckResult, error) {
	c.mu.Lock()
	*c.order = append(*c.order, host)
	c.mu.Unlock()
	return c.result, nil
}

func TestScanAllEndpoints_CRListError(t *testing.T) {
	scheme := newTestScheme()
	injectedErr := fmt.Errorf("injected CR list error")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*securityv1alpha1.TLSComplianceReportList); ok {
					return injectedErr
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		TLSChecker: &MockTLSChecker{},
		Workers:    1,
	}

	err := r.scanAllEndpoints(context.Background())
	if err == nil {
		t.Fatal("expected error when CR listing fails")
	}
	if !strings.Contains(err.Error(), "failed to list TLSComplianceReports") {
		t.Errorf("expected TLSComplianceReports error, got: %v", err)
	}
}

func TestCleanupOrphanedCRs_IngressOrphan(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-ingress",
			Namespace: testNamespace,
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{Host: "existing-ingress.example.com"},
			},
		},
	}

	now := metav1.Now()
	existingCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-ingress-443-aaa11111"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "existing-ingress.example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindIngress, SourceNamespace: testNamespace, SourceName: "existing-ingress",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant, FirstSeenAt: &now,
		},
	}

	orphanedCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "deleted-ingress-443-bbb22222"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "deleted-ingress.example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindIngress, SourceNamespace: testNamespace, SourceName: "deleted-ingress",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant, FirstSeenAt: &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ing, existingCR, orphanedCR).
		WithStatusSubresource(existingCR, orphanedCR).
		Build()

	r := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	if err := r.cleanupOrphanedCRs(ctx); err != nil {
		t.Fatalf("cleanupOrphanedCRs() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("failed to list CRs: %v", err)
	}

	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 CR remaining, got %d", len(crList.Items))
	}
	if crList.Items[0].Name != "existing-ingress-443-aaa11111" {
		t.Errorf("remaining CR = %v, want existing-ingress-443-aaa11111", crList.Items[0].Name)
	}
}

func TestCleanupOrphanedCRs_CRListError(t *testing.T) {
	scheme := newTestScheme()
	injectedErr := fmt.Errorf("injected CR list error")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*securityv1alpha1.TLSComplianceReportList); ok {
					return injectedErr
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	err := r.cleanupOrphanedCRs(context.Background())
	if err == nil {
		t.Fatal("expected error when CR listing fails")
	}
	if !strings.Contains(err.Error(), "failed to list TLSComplianceReports") {
		t.Errorf("expected TLSComplianceReports error, got: %v", err)
	}
}

func TestCleanupOrphanedCRs_GatewayGVKs(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()

	tlsRoute := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "TLSRoute",
		"metadata":   map[string]interface{}{"name": "existing-route", "namespace": "default"},
		"spec":       map[string]interface{}{"hostnames": []interface{}{"tls.example.com"}},
	}}

	existingCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-route-443-abc12345"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "tls.example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindTLSRoute, SourceNamespace: "default", SourceName: "existing-route",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant, FirstSeenAt: &now},
	}

	orphanedCR := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "deleted-route-443-def67890"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "gone.example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindTLSRoute, SourceNamespace: "default", SourceName: "deleted-route",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant, FirstSeenAt: &now},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tlsRoute, existingCR, orphanedCR).
		WithStatusSubresource(existingCR, orphanedCR).
		Build()

	r := &EndpointReconciler{
		Client:              fakeClient,
		Scheme:              scheme,
		GatewayAPIAvailable: true,
		GatewayGVKs: []schema.GroupVersionKind{
			{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "TLSRoute"},
		},
	}

	if err := r.cleanupOrphanedCRs(ctx); err != nil {
		t.Fatalf("cleanupOrphanedCRs() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 CR (orphan removed), got %d", len(crList.Items))
	}
	if crList.Items[0].Name != "existing-route-443-abc12345" {
		t.Errorf("remaining CR = %q, want existing-route-443-abc12345", crList.Items[0].Name)
	}
}

func TestAppendExtraPortEndpoints(t *testing.T) {
	base := []endpoint.Endpoint{{
		Host:            "svc.default",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "svc",
	}}

	t.Run("no annotation", func(t *testing.T) {
		got := endpoint.AppendExtraPorts(base, nil, "svc", "default", securityv1alpha1.SourceKindService)
		if len(got) != 1 {
			t.Fatalf("expected 1 endpoint, got %d", len(got))
		}
	})

	t.Run("extra ports added", func(t *testing.T) {
		ann := map[string]string{endpoint.AnnotationExtraPorts: "9443,8443"}
		got := endpoint.AppendExtraPorts(base, ann, "svc", "default", securityv1alpha1.SourceKindService)
		if len(got) != 3 {
			t.Fatalf("expected 3 endpoints, got %d", len(got))
		}
		if got[1].Port != 9443 || got[2].Port != 8443 {
			t.Errorf("unexpected ports: %d, %d", got[1].Port, got[2].Port)
		}
		if got[1].Host != "svc.default" {
			t.Errorf("expected host svc.default, got %s", got[1].Host)
		}
	})

	t.Run("duplicate port skipped", func(t *testing.T) {
		ann := map[string]string{endpoint.AnnotationExtraPorts: "443,9443"}
		got := endpoint.AppendExtraPorts(base, ann, "svc", "default", securityv1alpha1.SourceKindService)
		if len(got) != 2 {
			t.Fatalf("expected 2 endpoints (443 deduped), got %d", len(got))
		}
	})

	t.Run("empty base gets host from name", func(t *testing.T) {
		ann := map[string]string{endpoint.AnnotationExtraPorts: "9443"}
		got := endpoint.AppendExtraPorts(nil, ann, "svc", "default", securityv1alpha1.SourceKindService)
		if len(got) != 1 {
			t.Fatalf("expected 1 endpoint, got %d", len(got))
		}
		if got[0].Host != "svc.default" {
			t.Errorf("expected host svc.default, got %s", got[0].Host)
		}
	})
}

func TestEndpointReconciler_Reconcile_ServiceWithSkipAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: testNamespace,
			Annotations: map[string]string{
				endpoint.AnnotationSkip: "true",
			},
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
		t.Error("Reconcile() returned RequeueAfter != 0")
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("expected 0 TLSComplianceReports for skipped service, got %d", len(crList.Items))
	}
}

func TestEndpointReconciler_Reconcile_ServiceWithExtraPorts(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: testNamespace,
			Annotations: map[string]string{
				endpoint.AnnotationExtraPorts: "9443",
			},
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

	_, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list TLSComplianceReports: %v", err)
	}
	if len(crList.Items) != 2 {
		t.Fatalf("expected 2 TLSComplianceReports (443 + 9443), got %d", len(crList.Items))
	}

	ports := map[int32]bool{}
	for _, cr := range crList.Items {
		ports[cr.Spec.Port] = true
	}
	if !ports[443] || !ports[9443] {
		t.Errorf("expected ports 443 and 9443, got %v", ports)
	}
}

func TestEndpointReconciler_ScanPodEndpoints_SkipAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-pod",
			Namespace: testNamespace,
			Annotations: map[string]string{
				endpoint.AnnotationSkip: "true",
			},
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
	if len(crList.Items) != 0 {
		t.Errorf("expected 0 TLSComplianceReports for skipped pod, got %d", len(crList.Items))
	}
}

func TestAppendExtraPortEndpoints_SourceKindPropagation(t *testing.T) {
	ann := map[string]string{endpoint.AnnotationExtraPorts: "9443"}

	got := endpoint.AppendExtraPorts(nil, ann, "ing", "default", securityv1alpha1.SourceKindIngress)
	if len(got) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(got))
	}
	if got[0].SourceKind != securityv1alpha1.SourceKindIngress {
		t.Errorf("SourceKind = %v, want Ingress", got[0].SourceKind)
	}
}

func TestUpdateTargetStatus_SuccessCase(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{
			Name: "success-target",
		},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "example.com",
			Port: 443,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(target).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceTarget{}).
		Build()

	r := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	r.updateTargetStatus(ctx, "success-target", "report-abc", "Compliant", "")

	var updated securityv1alpha1.TLSComplianceTarget
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "success-target"}, &updated); err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	if updated.Status.ReportName != "report-abc" {
		t.Errorf("ReportName = %q, want report-abc", updated.Status.ReportName)
	}
	if updated.Status.ComplianceStatus != "Compliant" {
		t.Errorf("ComplianceStatus = %q, want Compliant", updated.Status.ComplianceStatus)
	}
	if updated.Status.Message != "" {
		t.Errorf("Message = %q, want empty", updated.Status.Message)
	}
	if updated.Status.LastScannedAt == nil {
		t.Error("LastScannedAt should be set")
	}
	found := false
	for _, c := range updated.Status.Conditions {
		if c.Type == "Ready" {
			found = true
			if c.Status != metav1.ConditionTrue {
				t.Errorf("Ready condition status = %v, want True", c.Status)
			}
			if c.Reason != "ScanComplete" {
				t.Errorf("Ready condition reason = %q, want ScanComplete", c.Reason)
			}
		}
	}
	if !found {
		t.Error("expected Ready condition to be set")
	}
}

func TestUpdateTargetStatus_ErrorCase(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-target",
		},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "example.com",
			Port: 443,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(target).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceTarget{}).
		Build()

	r := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	r.updateTargetStatus(ctx, "error-target", "report-abc", "", "connection refused")

	var updated securityv1alpha1.TLSComplianceTarget
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "error-target"}, &updated); err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	if updated.Status.ComplianceStatus != "" {
		t.Errorf("ComplianceStatus = %q, want empty on error", updated.Status.ComplianceStatus)
	}
	if updated.Status.Message != "connection refused" {
		t.Errorf("Message = %q, want 'connection refused'", updated.Status.Message)
	}
	found := false
	for _, c := range updated.Status.Conditions {
		if c.Type == "Ready" {
			found = true
			if c.Status != metav1.ConditionFalse {
				t.Errorf("Ready condition status = %v, want False", c.Status)
			}
			if c.Reason != "ScanFailed" {
				t.Errorf("Ready condition reason = %q, want ScanFailed", c.Reason)
			}
			if c.Message != "connection refused" {
				t.Errorf("Ready condition message = %q, want 'connection refused'", c.Message)
			}
		}
	}
	if !found {
		t.Error("expected Ready condition to be set")
	}
}

func TestUpdateTargetStatus_TargetNotFound(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceTarget{}).
		Build()

	r := &EndpointReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Should not panic when target does not exist
	r.updateTargetStatus(ctx, "nonexistent", "report-abc", "Compliant", "")
}

func TestHandleRoute_CreatesReport(t *testing.T) {
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

	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "route.openshift.io/v1",
		"kind":       "Route",
		"metadata":   map[string]interface{}{"name": "my-route", "namespace": "openshift-console"},
		"spec": map[string]interface{}{
			"host": "console.apps.example.com",
			"tls":  map[string]interface{}{"termination": "edge"},
		},
	}}

	_, err := reconciler.handleRoute(ctx, route)
	if err != nil {
		t.Fatalf("handleRoute() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 report, got %d", len(crList.Items))
	}
	cr := crList.Items[0]
	if cr.Spec.Host != "console.apps.example.com" {
		t.Errorf("host = %q, want console.apps.example.com", cr.Spec.Host)
	}
	if cr.Spec.Port != 443 {
		t.Errorf("port = %d, want 443", cr.Spec.Port)
	}
	if cr.Spec.SourceKind != securityv1alpha1.SourceKindRoute {
		t.Errorf("sourceKind = %q, want Route", cr.Spec.SourceKind)
	}
	if cr.Spec.SourceName != "my-route" {
		t.Errorf("sourceName = %q, want my-route", cr.Spec.SourceName)
	}
	if cr.Spec.SourceNamespace != "openshift-console" {
		t.Errorf("sourceNamespace = %q, want openshift-console", cr.Spec.SourceNamespace)
	}
}

func TestHandleRoute_SkipAnnotation(t *testing.T) {
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

	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "route.openshift.io/v1",
		"kind":       "Route",
		"metadata": map[string]interface{}{
			"name":      "skip-route",
			"namespace": "default",
			"annotations": map[string]interface{}{
				endpoint.AnnotationSkip: "true",
			},
		},
		"spec": map[string]interface{}{
			"host": "skip.example.com",
			"tls":  map[string]interface{}{"termination": "reencrypt"},
		},
	}}

	_, err := reconciler.handleRoute(ctx, route)
	if err != nil {
		t.Fatalf("handleRoute() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("expected 0 reports for skipped route, got %d", len(crList.Items))
	}
}

func TestHandleRoute_NoTLS(t *testing.T) {
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

	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "route.openshift.io/v1",
		"kind":       "Route",
		"metadata":   map[string]interface{}{"name": "plain-route", "namespace": "default"},
		"spec": map[string]interface{}{
			"host": "plain.example.com",
		},
	}}

	_, err := reconciler.handleRoute(ctx, route)
	if err != nil {
		t.Fatalf("handleRoute() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("expected 0 reports for route without TLS, got %d", len(crList.Items))
	}
}

func TestHandleRescan_RemovesAnnotationAndRescans(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-report",
			Annotations: map[string]string{
				RescanAnnotation: "true",
			},
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "test.example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: "default",
			SourceName:      "test-svc",
		},
	}

	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{
			SupportsTLS12: true,
			SupportsTLS13: true,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(report).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		TLSChecker:     checker,
		Workers:        1,
		CertExpiryDays: 30,
		Recorder:       events.NewFakeRecorder(10),
	}

	_, err := reconciler.handleRescan(ctx, report)
	if err != nil {
		t.Fatalf("handleRescan() error = %v", err)
	}

	var updated securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "test-report"}, &updated); err != nil {
		t.Fatalf("failed to get report: %v", err)
	}
	if _, hasAnnotation := updated.Annotations[RescanAnnotation]; hasAnnotation {
		t.Error("rescan annotation should have been removed")
	}
	if checker.CheckCount() == 0 {
		t.Error("expected TLS checker to be called at least once")
	}
}

func TestHandleRescan_AnnotationRemovalError(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-report",
			Annotations: map[string]string{
				RescanAnnotation: "true",
			},
		},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "test.example.com",
			Port: 443,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(report).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, ok := obj.(*securityv1alpha1.TLSComplianceReport); ok {
					return fmt.Errorf("injected update error")
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()

	reconciler := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	_, err := reconciler.handleRescan(ctx, report)
	if err == nil {
		t.Fatal("expected error when annotation removal fails")
	}
	if !strings.Contains(err.Error(), "removing rescan annotation") {
		t.Errorf("error = %q, want it to contain 'removing rescan annotation'", err.Error())
	}
}

func TestHandleHeadlessService_HappyPath(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = discoveryv1.AddToScheme(scheme)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless-svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Ports:     []corev1.ServicePort{{Port: 443, Name: "https"}},
		},
	}

	ready := true
	notReady := false
	epSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "headless-svc-abc",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "headless-svc"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc, epSlice).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	_, err := r.handleHeadlessService(context.Background(), svc)
	if err != nil {
		t.Fatalf("handleHeadlessService() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(context.Background(), &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 1 {
		t.Fatalf("expected 1 report (only ready endpoint), got %d", len(crList.Items))
	}
	if crList.Items[0].Spec.Host != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1", crList.Items[0].Spec.Host)
	}
}

func TestHandleHeadlessService_NoReadyEndpoints(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = discoveryv1.AddToScheme(scheme)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless-svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Ports:     []corev1.ServicePort{{Port: 443, Name: "https"}},
		},
	}

	notReady := false
	epSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "headless-svc-abc",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "headless-svc"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
			{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc, epSlice).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	_, err := r.handleHeadlessService(context.Background(), svc)
	if err != nil {
		t.Fatalf("handleHeadlessService() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(context.Background(), &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("expected 0 reports when no endpoints are ready, got %d", len(crList.Items))
	}
}

func TestHandleHeadlessService_MultipleSlices(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = discoveryv1.AddToScheme(scheme)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless-multi", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Ports:     []corev1.ServicePort{{Port: 443, Name: "https"}},
		},
	}

	ready := true
	slice1 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "headless-multi-slice1",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "headless-multi"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	slice2 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "headless-multi-slice2",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "headless-multi"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc, slice1, slice2).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	r := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		CertExpiryDays: 30,
	}

	_, err := r.handleHeadlessService(context.Background(), svc)
	if err != nil {
		t.Fatalf("handleHeadlessService() error = %v", err)
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(context.Background(), &crList); err != nil {
		t.Fatalf("failed to list reports: %v", err)
	}
	if len(crList.Items) != 2 {
		t.Fatalf("expected 2 reports from 2 slices, got %d", len(crList.Items))
	}

	hosts := map[string]bool{}
	for _, cr := range crList.Items {
		hosts[cr.Spec.Host] = true
	}
	if !hosts["10.0.0.1"] || !hosts["10.0.0.2"] {
		t.Errorf("expected reports for 10.0.0.1 and 10.0.0.2, got hosts %v", hosts)
	}
}

func TestGetNodeAddresses(t *testing.T) {
	scheme := newTestScheme()
	nodes := []client.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "203.0.113.1"},
					{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "10.0.0.2"},
					{Type: corev1.NodeHostName, Address: "node-2.local"},
				},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodes...).Build()
	r := &EndpointReconciler{Client: fakeClient, Scheme: scheme}
	addrs, err := r.getNodeAddresses(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 3 {
		t.Fatalf("expected 3 addresses (1 external + 2 internal), got %d: %v", len(addrs), addrs)
	}
	addrSet := map[string]bool{}
	for _, a := range addrs {
		addrSet[a] = true
	}
	if !addrSet["203.0.113.1"] || !addrSet["10.0.0.1"] || !addrSet["10.0.0.2"] {
		t.Errorf("expected 203.0.113.1, 10.0.0.1, 10.0.0.2 in results, got %v", addrs)
	}
	if addrSet["node-2.local"] {
		t.Errorf("hostname should not be included in addresses")
	}
}

func TestGetNodeAddresses_Deduplicate(t *testing.T) {
	scheme := newTestScheme()
	nodes := []client.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.1"},
					{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodes...).Build()
	r := &EndpointReconciler{Client: fakeClient, Scheme: scheme}
	addrs, err := r.getNodeAddresses(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 deduplicated address, got %d: %v", len(addrs), addrs)
	}
}

func TestGetNodeAddresses_NoNodes(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &EndpointReconciler{Client: fakeClient, Scheme: scheme}
	addrs, err := r.getNodeAddresses(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("expected 0 addresses, got %d", len(addrs))
	}
}

// Ensure _ satisfies the client.Object interface for compile-time check
var _ client.Object = &securityv1alpha1.TLSComplianceReport{}
