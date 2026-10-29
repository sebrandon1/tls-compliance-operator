package controller

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

func restrictTestReport(name, host string, port int32, kind securityv1alpha1.SourceKind, sourceName string) *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            host,
			Port:            port,
			SourceKind:      kind,
			SourceNamespace: testNamespace,
			SourceName:      sourceName,
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{ComplianceStatus: securityv1alpha1.ComplianceStatusPending},
	}
}

func restrictTestService(name string, svcType corev1.ServiceType) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec:       corev1.ServiceSpec{Type: svcType},
	}
	if svcType == corev1.ServiceTypeExternalName {
		svc.Spec.ExternalName = "api.example.com"
	}
	return svc
}

func TestRestrictDial(t *testing.T) {
	objs := []client.Object{
		restrictTestReport("target", "api.example.com", 443, securityv1alpha1.SourceKindTarget, "t"),
		restrictTestReport("externalname", "api.example.com", 443, securityv1alpha1.SourceKindService, "ext"),
		restrictTestReport("clusterip", "web.default", 443, securityv1alpha1.SourceKindService, "web"),
		restrictTestReport("svc-gone", "gone.default", 443, securityv1alpha1.SourceKindService, "gone"),
		restrictTestReport("pod", "10.128.0.5", 8443, securityv1alpha1.SourceKindPod, "pod"),
		restrictTestReport("ingress", "app.example.com", 443, securityv1alpha1.SourceKindIngress, "ing"),
		restrictTestService("ext", corev1.ServiceTypeExternalName),
		restrictTestService("web", corev1.ServiceTypeClusterIP),
	}
	r := &EndpointReconciler{
		Client: fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(objs...).Build(),
	}

	tests := []struct {
		crName string
		want   bool
	}{
		{"target", true},
		{"externalname", true},
		{"clusterip", false},
		{"svc-gone", false},
		{"pod", false},
		{"ingress", false},
		{"missing-report", false},
	}
	for _, tt := range tests {
		t.Run(tt.crName, func(t *testing.T) {
			if got := r.restrictDial(context.Background(), tt.crName); got != tt.want {
				t.Errorf("restrictDial(%q) = %v, want %v", tt.crName, got, tt.want)
			}
		})
	}
}

// TestPerformTLSCheck_RestrictedDialBlocksTarget runs the real checker against
// a loopback TLS server: the Target report must be blocked without retries,
// while a ClusterIP Service report at the same address is probed normally.
func TestPerformTLSCheck_RestrictedDialBlocksTarget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(
			restrictTestReport("target", host, int32(port), securityv1alpha1.SourceKindTarget, "t"),
			restrictTestReport("clusterip", host, int32(port), securityv1alpha1.SourceKindService, "web"),
			restrictTestService("web", corev1.ServiceTypeClusterIP),
		).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()

	recorder := events.NewFakeRecorder(10)
	r := &EndpointReconciler{
		Client:         fakeClient,
		Scheme:         newTestScheme(),
		TLSChecker:     tlscheck.NewTLSChecker(2 * time.Second),
		Recorder:       recorder,
		CertExpiryDays: 30,
		MaxRetries:     3,
		RetryBackoff:   time.Hour, // a retry would hang the test
		ScanInterval:   time.Hour,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r.performTLSCheck(ctx, "target", host, port, testNamespace, false)
	for len(recorder.Events) > 0 {
		if ev := <-recorder.Events; strings.Contains(ev, EventReasonRetryExhausted) {
			t.Errorf("blocked check emitted a retry-exhausted event: %s", ev)
		}
	}
	r.performTLSCheck(ctx, "clusterip", host, port, testNamespace, false)

	var blocked securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "target"}, &blocked); err != nil {
		t.Fatalf("get target report: %v", err)
	}
	if blocked.Status.ComplianceStatus != securityv1alpha1.ComplianceStatusUnreachable {
		t.Errorf("target status = %q, want Unreachable", blocked.Status.ComplianceStatus)
	}
	if !strings.Contains(blocked.Status.LastError, "reserved address") || !strings.Contains(blocked.Status.LastError, host) {
		t.Errorf("target LastError = %q, want it to name the blocked reserved address %s", blocked.Status.LastError, host)
	}
	if blocked.Status.TLSVersions.TLS12 || blocked.Status.TLSVersions.TLS13 {
		t.Error("target report recorded TLS support; the probe should never have connected")
	}

	var probed securityv1alpha1.TLSComplianceReport
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "clusterip"}, &probed); err != nil {
		t.Fatalf("get clusterip report: %v", err)
	}
	if !probed.Status.TLSVersions.TLS12 && !probed.Status.TLSVersions.TLS13 {
		t.Errorf("clusterip report was not probed: status %q, lastError %q", probed.Status.ComplianceStatus, probed.Status.LastError)
	}
}

func TestHandleTarget_UnsafeHostSkipped(t *testing.T) {
	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "loopback-target"},
		Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "127.0.0.1", Port: int32PointerForTest(8081)},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(target).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}, &securityv1alpha1.TLSComplianceTarget{}).
		Build()
	checker := &MockTLSChecker{}
	r := &EndpointReconciler{
		Client:     fakeClient,
		Scheme:     newTestScheme(),
		TLSChecker: checker,
		Recorder:   events.NewFakeRecorder(10),
		ManagerCtx: context.Background(),
	}

	if _, err := r.handleTarget(context.Background(), target); err != nil {
		t.Fatalf("handleTarget() error = %v", err)
	}

	var reports securityv1alpha1.TLSComplianceReportList
	if err := fakeClient.List(context.Background(), &reports); err != nil {
		t.Fatalf("list reports: %v", err)
	}
	if len(reports.Items) != 0 {
		t.Errorf("got %d reports, want 0 for an unsafe Target", len(reports.Items))
	}
	if n := checker.CheckCount(); n != 0 {
		t.Errorf("checker called %d times, want 0", n)
	}

	var got securityv1alpha1.TLSComplianceTarget
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: target.Name}, &got); err != nil {
		t.Fatalf("get target: %v", err)
	}
	if !strings.Contains(got.Status.Message, "internal or reserved") {
		t.Errorf("target status message = %q, want it to explain the skip", got.Status.Message)
	}
}
