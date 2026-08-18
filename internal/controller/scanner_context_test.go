package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

// blockingChecker waits until ctx is cancelled (or released) so tests can
// observe which context an async probe actually uses.
type blockingChecker struct {
	started chan struct{}
	release chan struct{}
	err     atomic.Value
}

func newBlockingChecker() *blockingChecker {
	return &blockingChecker{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (c *blockingChecker) CheckEndpoint(ctx context.Context, _ string, _ int) (*tlscheck.TLSCheckResult, error) {
	close(c.started)
	select {
	case <-ctx.Done():
		c.err.Store(ctx.Err())
		return nil, ctx.Err()
	case <-c.release:
		return &tlscheck.TLSCheckResult{SupportsTLS12: true, SupportsTLS13: true}, nil
	}
}

func (c *blockingChecker) ctxErr() error {
	v := c.err.Load()
	if v == nil {
		return nil
	}
	return v.(error)
}

func newAsyncCheckReconciler(t *testing.T, checker tlscheck.Checker, managerCtx context.Context, timeout time.Duration) *EndpointReconciler {
	t.Helper()
	scheme := newTestScheme()
	cr := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "async-test"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: "default",
			SourceName:      "svc",
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()
	return &EndpointReconciler{
		Client:       c,
		Scheme:       scheme,
		TLSChecker:   checker,
		Workers:      1,
		ManagerCtx:   managerCtx,
		checkTimeout: timeout,
	}
}

func waitStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("checker did not start")
	}
}

func waitWorkerIdle(t *testing.T, r *EndpointReconciler) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if len(r.checkSem) == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("async worker did not finish")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitCheckerErr(t *testing.T, checker *blockingChecker, want error) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if errors.Is(checker.ctxErr(), want) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("checker ctx err = %v, want %v", checker.ctxErr(), want)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestTryAsyncCheck_ManagerCtxCancelAbortsCheck(t *testing.T) {
	managerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	checker := newBlockingChecker()
	r := newAsyncCheckReconciler(t, checker, managerCtx, time.Minute)

	if err := r.tryAsyncCheck("async-test", "example.com", 443, "default"); err != nil {
		t.Fatalf("tryAsyncCheck() error = %v", err)
	}
	waitStarted(t, checker.started)

	cancel()
	waitCheckerErr(t, checker, context.Canceled)
	waitWorkerIdle(t, r)
}

func TestTryAsyncCheck_ReconcileCtxCancelDoesNotAbort(t *testing.T) {
	managerCtx := context.Background()
	reconcileCtx, cancelReconcile := context.WithCancel(context.Background())
	defer cancelReconcile()

	checker := newBlockingChecker()
	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{}).
		Build()
	r := &EndpointReconciler{
		Client:       c,
		Scheme:       scheme,
		TLSChecker:   checker,
		Workers:      1,
		ManagerCtx:   managerCtx,
		checkTimeout: time.Minute,
	}
	ep := endpoint.Endpoint{
		Host:            "example.com",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "svc",
	}
	if err := r.processEndpoint(reconcileCtx, &ep); err != nil {
		t.Fatalf("processEndpoint() error = %v", err)
	}
	waitStarted(t, checker.started)

	cancelReconcile()
	time.Sleep(50 * time.Millisecond)
	if err := checker.ctxErr(); err != nil {
		t.Fatalf("async check aborted after reconcile ctx cancel: %v", err)
	}

	close(checker.release)
	waitWorkerIdle(t, r)
}

func TestTryAsyncCheck_TimeoutAbortsHungProbe(t *testing.T) {
	checker := newBlockingChecker()
	r := newAsyncCheckReconciler(t, checker, context.Background(), 50*time.Millisecond)

	if err := r.tryAsyncCheck("async-test", "example.com", 443, "default"); err != nil {
		t.Fatalf("tryAsyncCheck() error = %v", err)
	}
	waitStarted(t, checker.started)
	waitCheckerErr(t, checker, context.DeadlineExceeded)
	waitWorkerIdle(t, r)
}

func TestTryAsyncCheck_NilManagerCtxUsesBackground(t *testing.T) {
	checker := &MockTLSChecker{
		Result: &tlscheck.TLSCheckResult{SupportsTLS12: true, SupportsTLS13: true},
	}
	r := newAsyncCheckReconciler(t, checker, nil, 50*time.Millisecond)

	if err := r.tryAsyncCheck("async-test", "example.com", 443, "default"); err != nil {
		t.Fatalf("tryAsyncCheck() error = %v", err)
	}

	deadline := time.After(2 * time.Second)
	for checker.CheckCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("check did not run with nil ManagerCtx")
		case <-time.After(10 * time.Millisecond):
		}
	}
	waitWorkerIdle(t, r)
}

func TestPerformTLSCheck_CallerCtxCancelAborts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	checker := newBlockingChecker()
	r := newAsyncCheckReconciler(t, checker, context.Background(), time.Minute)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.performTLSCheck(ctx, "async-test", "example.com", 443, "default", false)
	}()
	waitStarted(t, checker.started)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("performTLSCheck did not return after caller ctx cancel")
	}
	if !errors.Is(checker.ctxErr(), context.Canceled) {
		t.Fatalf("checker ctx err = %v, want context.Canceled", checker.ctxErr())
	}
}

func TestAsyncCheckTimeout_DefaultAndOverride(t *testing.T) {
	r := &EndpointReconciler{}
	// MaxRetries=0, MaxBackoff unset → 1 attempt * DefaultTimeout
	want := tlscheck.DefaultTimeout
	if got := r.asyncCheckTimeout(); got != want {
		t.Errorf("asyncCheckTimeout() = %v, want %v", got, want)
	}

	r.MaxRetries = 3
	r.MaxBackoff = 5 * time.Minute
	want = 4*tlscheck.DefaultTimeout + 3*5*time.Minute
	if got := r.asyncCheckTimeout(); got != want {
		t.Errorf("asyncCheckTimeout() with retries = %v, want %v", got, want)
	}

	r.checkTimeout = 2 * time.Second
	if got := r.asyncCheckTimeout(); got != 2*time.Second {
		t.Errorf("asyncCheckTimeout() override = %v, want 2s", got)
	}
}

func TestManagerCtx_NilFallsBackToBackground(t *testing.T) {
	r := &EndpointReconciler{}
	if r.managerCtx() != context.Background() {
		t.Fatal("nil ManagerCtx should fall back to context.Background")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.ManagerCtx = ctx
	if r.managerCtx() != ctx {
		t.Fatal("managerCtx() should return ManagerCtx when set")
	}
}
