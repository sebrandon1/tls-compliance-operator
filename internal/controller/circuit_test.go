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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	r := &EndpointReconciler{}
	for i := 0; i < circuitBreakerThreshold; i++ {
		if r.circuitOpen("ep") {
			t.Fatalf("circuit opened after %d failures, want closed until %d", i, circuitBreakerThreshold)
		}
		r.recordCircuitFailure("ep")
	}
	if !r.circuitOpen("ep") {
		t.Fatal("expected circuit open after threshold failures")
	}
}

func TestCircuitBreaker_SuccessClears(t *testing.T) {
	r := &EndpointReconciler{}
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.recordCircuitFailure("ep")
	}
	r.recordCircuitSuccess("ep")
	if r.circuitOpen("ep") {
		t.Fatal("expected circuit closed after success")
	}
	r.recordCircuitFailure("ep")
	if r.circuitOpen("ep") {
		t.Fatal("expected circuit to stay closed after a single failure following reset")
	}
}

func TestCircuitBreaker_ExpiredAllowsProbe(t *testing.T) {
	r := &EndpointReconciler{}
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.recordCircuitFailure("ep")
	}
	r.circuitMu.Lock()
	st := r.circuits["ep"]
	st.nextEligible = time.Now().Add(-time.Second)
	r.circuits["ep"] = st
	r.circuitMu.Unlock()
	if r.circuitOpen("ep") {
		t.Fatal("expected circuit closed after cooldown elapsed")
	}
}

func TestSkipIfCircuitOpen(t *testing.T) {
	r := &EndpointReconciler{}
	if r.skipIfCircuitOpen("ep") {
		t.Fatal("expected skip=false when circuit is closed")
	}
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.recordCircuitFailure("ep")
	}
	if !r.skipIfCircuitOpen("ep") {
		t.Fatal("expected skip=true when circuit is open")
	}
}

func newCircuitCheckReconciler(t *testing.T, crName, host string, checker tlscheck.Checker) *EndpointReconciler {
	t.Helper()
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            host,
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: testNamespace,
			SourceName:      "svc",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
		},
	}
	scheme := newTestScheme()
	return &EndpointReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cr).
			WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
			Build(),
		Scheme:       scheme,
		TLSChecker:   checker,
		MaxRetries:   0,
		RetryBackoff: time.Millisecond,
	}
}

func TestPerformTLSCheck_OpensCircuitThenSkips(t *testing.T) {
	ctx := context.Background()
	crName := "circuit-test-cr"
	host := "timeout.example.com"
	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{FailureReason: tlscheck.FailureReasonTimeout},
		Err:    fmt.Errorf("connection timed out"),
	}
	r := newCircuitCheckReconciler(t, crName, host, checker)

	for i := 0; i < circuitBreakerThreshold; i++ {
		r.performTLSCheck(ctx, crName, host, 443, testNamespace, false)
	}
	if checker.CheckCount() != int32(circuitBreakerThreshold) {
		t.Fatalf("expected %d checks before circuit open, got %d", circuitBreakerThreshold, checker.CheckCount())
	}
	if err := r.tryAsyncCheck(crName, host, 443, testNamespace); err != nil {
		t.Fatalf("tryAsyncCheck: %v", err)
	}
	if checker.CheckCount() != int32(circuitBreakerThreshold) {
		t.Errorf("expected no additional check while circuit is open, got %d calls", checker.CheckCount())
	}
}

func TestPerformTLSCheck_SuccessClearsCircuit(t *testing.T) {
	ctx := context.Background()
	crName := "circuit-reset-cr"
	host := "ok.example.com"
	timeoutResult := &tlscheck.TLSCheckResult{FailureReason: tlscheck.FailureReasonTimeout}
	okResult := &tlscheck.TLSCheckResult{SupportsTLS12: true, SupportsTLS13: true, CipherSuites: map[string][]string{}}
	checker := &SequencedMockTLSChecker{
		Results: []*tlscheck.TLSCheckResult{timeoutResult, timeoutResult, okResult, timeoutResult},
		Errors:  []error{fmt.Errorf("timeout"), fmt.Errorf("timeout"), nil, fmt.Errorf("timeout")},
	}
	r := newCircuitCheckReconciler(t, crName, host, checker)

	r.performTLSCheck(ctx, crName, host, 443, testNamespace, false)
	r.performTLSCheck(ctx, crName, host, 443, testNamespace, false)
	r.performTLSCheck(ctx, crName, host, 443, testNamespace, false)
	if r.circuitOpen(crName) {
		t.Fatal("expected circuit closed after success")
	}
	r.performTLSCheck(ctx, crName, host, 443, testNamespace, false)
	if r.circuitOpen(crName) {
		t.Fatal("expected circuit still closed after one failure following success")
	}
}

func TestTryAsyncCheck_SkipsOpenCircuit(t *testing.T) {
	r := &EndpointReconciler{}
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.recordCircuitFailure("busy")
	}
	if err := r.tryAsyncCheck("busy", "h", 443, "ns"); err != nil {
		t.Fatalf("expected nil when circuit open, got %v", err)
	}
	if r.checkSem != nil {
		t.Fatal("should not acquire a worker when circuit is open")
	}
}

func TestIsCircuitFailure(t *testing.T) {
	if !isCircuitFailure(tlscheck.FailureReasonTimeout) || !isCircuitFailure(tlscheck.FailureReasonUnreachable) {
		t.Fatal("Timeout and Unreachable should trip the circuit")
	}
	if isCircuitFailure(tlscheck.FailureReasonClosed) || isCircuitFailure(tlscheck.FailureReasonNone) {
		t.Fatal("Closed and success should not trip the circuit")
	}
}

func TestPerformTLSCheck_UnreachableOpensCircuit(t *testing.T) {
	ctx := context.Background()
	crName := "unreachable-circuit-cr"
	host := "down.example.com"
	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{FailureReason: tlscheck.FailureReasonUnreachable},
		Err:    fmt.Errorf("no route to host"),
	}
	r := newCircuitCheckReconciler(t, crName, host, checker)
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.performTLSCheck(ctx, crName, host, 443, testNamespace, false)
	}
	if !r.circuitOpen(crName) {
		t.Fatal("expected circuit open after Unreachable failures")
	}
}

func TestPerformTLSCheck_ClosedDoesNotTripCircuit(t *testing.T) {
	ctx := context.Background()
	crName := "closed-circuit-cr"
	host := "closed.example.com"
	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{FailureReason: tlscheck.FailureReasonClosed},
		Err:    fmt.Errorf("connection refused"),
	}
	r := newCircuitCheckReconciler(t, crName, host, checker)
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.performTLSCheck(ctx, crName, host, 443, testNamespace, false)
	}
	if r.circuitOpen(crName) {
		t.Fatal("Closed failures should not open the circuit")
	}
}

func TestScanAllEndpoints_SkipsOpenCircuit(t *testing.T) {
	ctx := context.Background()
	crName := "scan-skip-cr"
	host := "skip.example.com"
	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{SupportsTLS12: true, SupportsTLS13: true, CipherSuites: map[string][]string{}},
	}
	r := newCircuitCheckReconciler(t, crName, host, checker)
	r.Workers = 1
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.recordCircuitFailure(crName)
	}
	if err := r.scanAllEndpoints(ctx); err != nil {
		t.Fatalf("scanAllEndpoints: %v", err)
	}
	if checker.CheckCount() != 0 {
		t.Errorf("expected 0 checks while circuit is open, got %d", checker.CheckCount())
	}
}

func TestCleanupOrphanedCRs_ForgetsCircuit(t *testing.T) {
	ctx := context.Background()
	crName := "gone-svc-443"
	host := "gone.example.com"
	r := newCircuitCheckReconciler(t, crName, host, &MockTLSChecker{})
	for i := 0; i < circuitBreakerThreshold; i++ {
		r.recordCircuitFailure(crName)
	}
	if err := r.cleanupOrphanedCRs(ctx); err != nil {
		t.Fatalf("cleanupOrphanedCRs: %v", err)
	}
	if r.circuitOpen(crName) {
		t.Fatal("expected circuit entry removed when the CR is deleted")
	}
}
