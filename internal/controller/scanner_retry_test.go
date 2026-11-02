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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

var closedResult = &tlscheck.TLSCheckResult{FailureReason: tlscheck.FailureReasonClosed}

func TestScanAllEndpoints_DoesNotRetryInline(t *testing.T) {
	checker := &MockTLSChecker{Result: closedResult, Err: errors.New("connection refused")}
	r := newCircuitCheckReconciler(t, "stale-pod-443", "10.0.0.1", checker)
	r.Workers = 1
	r.MaxRetries = 3
	// A backoff this long would hang the test if the scan retried inline.
	r.RetryBackoff = time.Hour
	recorder := events.NewFakeRecorder(10)
	r.Recorder = recorder

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.scanAllEndpoints(ctx); err != nil {
		t.Fatalf("scanAllEndpoints: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("scanAllEndpoints slept through retry backoff")
	}
	if got := checker.CheckCount(); got != 1 {
		t.Errorf("expected a single probe in the periodic scan, got %d", got)
	}

	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(ctx, client.ObjectKey{Name: "stale-pod-443"}, &cr); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if cr.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusClosed {
		t.Errorf("status = %s, want %s", cr.Status.ComplianceStatus, securityv1alpha1.ComplianceStatusClosed)
	}

	close(recorder.Events)
	for ev := range recorder.Events {
		if strings.Contains(ev, EventReasonRetryExhausted) {
			t.Errorf("unexpected %s event without retries: %s", EventReasonRetryExhausted, ev)
		}
	}
}

func TestPerformTLSCheck_RetriesOutsidePeriodicScan(t *testing.T) {
	checker := &MockTLSChecker{Result: closedResult, Err: errors.New("connection refused")}
	r := newCircuitCheckReconciler(t, "svc-443", "10.0.0.2", checker)
	r.MaxRetries = 2
	r.RetryBackoff = time.Millisecond

	r.performTLSCheck(context.Background(), "svc-443", "10.0.0.2", 443, testNamespace, false)
	if got := checker.CheckCount(); got != 3 {
		t.Errorf("expected 3 probes (1 + 2 retries), got %d", got)
	}
}

// deletingChecker deletes the report on its first probe, as cleanup does when
// the source Pod goes away during a retry backoff.
type deletingChecker struct {
	r      *EndpointReconciler
	crName string
	calls  atomic.Int32
}

func (c *deletingChecker) CheckEndpoint(ctx context.Context, _ string, _ int) (*tlscheck.TLSCheckResult, error) {
	if c.calls.Add(1) == 1 {
		cr := &securityv1alpha1.TLSComplianceReport{}
		cr.Name = c.crName
		_ = c.r.Delete(ctx, cr)
	}
	return closedResult, errors.New("connection refused")
}

func TestPerformTLSCheck_StopsRetryingWhenReportDeleted(t *testing.T) {
	crName := "rolled-pod-443"
	checker := &deletingChecker{crName: crName}
	r := newCircuitCheckReconciler(t, crName, "10.0.0.3", checker)
	checker.r = r
	r.MaxRetries = 3
	r.RetryBackoff = time.Millisecond

	r.performTLSCheck(context.Background(), crName, "10.0.0.3", 443, testNamespace, false)
	if got := checker.calls.Load(); got != 1 {
		t.Errorf("expected retries to stop after the report was deleted, got %d probes", got)
	}
}

func TestCheckAttempts(t *testing.T) {
	r := &EndpointReconciler{MaxRetries: 3}
	if got := r.checkAttempts(context.Background()); got != 4 {
		t.Errorf("checkAttempts = %d, want 4", got)
	}
	if got := r.checkAttempts(withoutRetries(context.Background())); got != 1 {
		t.Errorf("checkAttempts without retries = %d, want 1", got)
	}
}
