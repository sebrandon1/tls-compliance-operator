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
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

func newLocalhostReconciler(t *testing.T, crName string, addrs []string, discover bool) *EndpointReconciler {
	t.Helper()
	now := metav1.Now()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: crName},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "10.244.1.5",
			Port:            8443,
			SourceKind:      securityv1alpha1.SourceKindPod,
			SourceNamespace: "default",
			SourceName:      "loopback",
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			ListenAddresses:  addrs,
		},
	}
	scheme := newTestScheme()
	return &EndpointReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cr).
			WithStatusSubresource(cr).
			Build(),
		Scheme:                 scheme,
		DiscoverListeningPorts: discover,
		ScanInterval:           time.Hour,
		CertExpiryDays:         30,
	}
}

func TestApplyCheckResult_LocalhostOnlyClassification(t *testing.T) {
	tests := []struct {
		name      string
		addrs     []string
		discover  bool
		reason    tlscheck.FailureReason
		hasResult bool
		want      securityv1alpha1.ComplianceStatus
	}{
		{
			name: "closed on loopback", addrs: []string{"127.0.0.1"}, discover: true,
			reason: tlscheck.FailureReasonClosed, hasResult: true,
			want: securityv1alpha1.ComplianceStatusLocalhostOnly,
		},
		{
			name: "timeout on loopback", addrs: []string{"127.0.0.1", "::1"}, discover: true,
			reason: tlscheck.FailureReasonTimeout, hasResult: true,
			want: securityv1alpha1.ComplianceStatusLocalhostOnly,
		},
		{
			name: "unreachable on loopback", addrs: []string{"127.0.0.1"}, discover: true,
			reason: tlscheck.FailureReasonUnreachable, hasResult: true,
			want: securityv1alpha1.ComplianceStatusLocalhostOnly,
		},
		{
			name: "nil result on loopback", addrs: []string{"127.0.0.1"}, discover: true,
			want: securityv1alpha1.ComplianceStatusLocalhostOnly,
		},
		{
			name: "wildcard stays closed", addrs: []string{"0.0.0.0"}, discover: true,
			reason: tlscheck.FailureReasonClosed, hasResult: true,
			want: securityv1alpha1.ComplianceStatusClosed,
		},
		{
			name: "mixed bindings stay closed", addrs: []string{"127.0.0.1", "0.0.0.0"}, discover: true,
			reason: tlscheck.FailureReasonClosed, hasResult: true,
			want: securityv1alpha1.ComplianceStatusClosed,
		},
		{
			name: "unknown addresses stay closed", addrs: nil, discover: true,
			reason: tlscheck.FailureReasonClosed, hasResult: true,
			want: securityv1alpha1.ComplianceStatusClosed,
		},
		{
			name: "discovery disabled stays closed", addrs: []string{"127.0.0.1"}, discover: false,
			reason: tlscheck.FailureReasonClosed, hasResult: true,
			want: securityv1alpha1.ComplianceStatusClosed,
		},
		{
			name: "no TLS is not reclassified", addrs: []string{"127.0.0.1"}, discover: true,
			reason: tlscheck.FailureReasonNoTLS, hasResult: true,
			want: securityv1alpha1.ComplianceStatusNoTLS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crName := "loopback-8443"
			r := newLocalhostReconciler(t, crName, tt.addrs, tt.discover)
			recorder := events.NewFakeRecorder(10)
			r.Recorder = recorder
			r.MaxRetries = 2

			var result *tlscheck.TLSCheckResult
			if tt.hasResult {
				result = &tlscheck.TLSCheckResult{FailureReason: tt.reason}
			}
			r.applyCheckResult(context.Background(), crName, "10.244.1.5", 8443, result, errors.New("connection refused"))

			var cr securityv1alpha1.TLSComplianceReport
			if err := r.Get(context.Background(), client.ObjectKey{Name: crName}, &cr); err != nil {
				t.Fatalf("get report: %v", err)
			}
			if cr.Status.ComplianceStatus != tt.want {
				t.Errorf("ComplianceStatus = %s, want %s", cr.Status.ComplianceStatus, tt.want)
			}
			if cr.Status.CheckCount != 1 {
				t.Errorf("CheckCount = %d, want 1", cr.Status.CheckCount)
			}
			if cr.Status.LastError == "" {
				t.Error("LastError should retain the probe error")
			}

			close(recorder.Events)
			for ev := range recorder.Events {
				if tt.want == securityv1alpha1.ComplianceStatusLocalhostOnly &&
					strings.Contains(ev, EventReasonRetryExhausted) {
					t.Errorf("unexpected %s event for a localhost-only endpoint: %s", EventReasonRetryExhausted, ev)
				}
			}
		})
	}
}

func TestApplyCheckResult_SuccessWinsOverLoopbackAddresses(t *testing.T) {
	crName := "loopback-8443"
	r := newLocalhostReconciler(t, crName, []string{"127.0.0.1"}, true)

	result := &tlscheck.TLSCheckResult{
		SupportsTLS12: true,
		SupportsTLS13: true,
		CipherSuites:  map[string][]string{"TLS1.3": {"TLS_AES_128_GCM_SHA256"}},
	}
	r.applyCheckResult(context.Background(), crName, "10.244.1.5", 8443, result, nil)

	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: crName}, &cr); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if cr.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusCompliant {
		t.Errorf("ComplianceStatus = %s, want Compliant", cr.Status.ComplianceStatus)
	}
}

func TestIsLoopbackOnlyReport_NilClient(t *testing.T) {
	r := &EndpointReconciler{DiscoverListeningPorts: true}
	if r.isLoopbackOnlyReport(context.Background(), "any") {
		t.Error("isLoopbackOnlyReport() = true with no client, want false")
	}
}

func TestProcessEndpoint_PersistsListenAddresses(t *testing.T) {
	ep := &endpoint.Endpoint{
		Host:                 "10.244.1.5",
		Port:                 8443,
		SourceKind:           securityv1alpha1.SourceKindPod,
		SourceNamespace:      "default",
		SourceName:           "loopback",
		ListenAddresses:      []string{"127.0.0.1"},
		ListenAddressesKnown: true,
	}
	crName := endpoint.GenerateCRName(ep)
	scheme := newTestScheme()
	r := &EndpointReconciler{
		Client:       fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).Build(),
		Scheme:       scheme,
		ScanInterval: time.Hour,
	}

	if err := r.processEndpoint(context.Background(), ep); err != nil {
		t.Fatalf("processEndpoint(create) error = %v", err)
	}
	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: crName}, &cr); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if want := []string{"127.0.0.1"}; !reflect.DeepEqual(cr.Status.ListenAddresses, want) {
		t.Errorf("create ListenAddresses = %v, want %v", cr.Status.ListenAddresses, want)
	}

	// A later observation replaces the set, including an authoritative clear.
	ep.ListenAddresses = nil
	if err := r.processEndpoint(context.Background(), ep); err != nil {
		t.Fatalf("processEndpoint(update) error = %v", err)
	}
	if err := r.Get(context.Background(), client.ObjectKey{Name: crName}, &cr); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if len(cr.Status.ListenAddresses) != 0 {
		t.Errorf("update ListenAddresses = %v, want empty", cr.Status.ListenAddresses)
	}

	// Discovery that did not run must not erase the last known addresses.
	if err := r.updateStatusWithRetry(context.Background(), crName, func(cr *securityv1alpha1.TLSComplianceReport) {
		cr.Status.ListenAddresses = []string{"127.0.0.1"}
	}); err != nil {
		t.Fatalf("seed addresses: %v", err)
	}
	ep.ListenAddressesKnown = false
	if err := r.processEndpoint(context.Background(), ep); err != nil {
		t.Fatalf("processEndpoint(unknown) error = %v", err)
	}
	if err := r.Get(context.Background(), client.ObjectKey{Name: crName}, &cr); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if want := []string{"127.0.0.1"}; !reflect.DeepEqual(cr.Status.ListenAddresses, want) {
		t.Errorf("unknown-observation ListenAddresses = %v, want preserved %v", cr.Status.ListenAddresses, want)
	}
}

func TestRetryTLSCheck_LoopbackOnlyProbesOnce(t *testing.T) {
	crName := "loopback-8443"
	r := newLocalhostReconciler(t, crName, []string{"127.0.0.1"}, true)
	checker := &MockTLSChecker{Result: closedResult, Err: errors.New("connection refused")}
	r.TLSChecker = checker
	r.MaxRetries = 3
	// A backoff this long would hang the test if the loop retried.
	r.RetryBackoff = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.performTLSCheck(ctx, crName, "10.244.1.5", 8443, "default", false)

	if got := checker.CheckCount(); got != 1 {
		t.Errorf("expected a single probe for a loopback-only listener, got %d", got)
	}
	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		t.Fatalf("get report: %v", err)
	}
	if cr.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusLocalhostOnly {
		t.Errorf("ComplianceStatus = %s, want LocalhostOnly", cr.Status.ComplianceStatus)
	}
}
