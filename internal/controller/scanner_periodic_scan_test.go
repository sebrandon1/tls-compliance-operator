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
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

// countingPodListClient returns a fake client that increments podListCalls each
// time the scanner lists Pods — one list occurs per scan cycle in scanPodEndpoints.
func countingPodListClient(t *testing.T, objects ...client.Object) (client.Client, *atomic.Int32) {
	t.Helper()
	var podListCalls atomic.Int32
	c := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(objects...).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					podListCalls.Add(1)
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	return c, &podListCalls
}

// newWindowedReconciler builds a minimal EndpointReconciler with the given scan window.
func newWindowedReconciler(t *testing.T, start, end, tz string) (*EndpointReconciler, *atomic.Int32) {
	t.Helper()
	c, podListCalls := countingPodListClient(t)
	r := &EndpointReconciler{
		Client:             c,
		Scheme:             newTestScheme(),
		TLSChecker:         &MockTLSChecker{Result: &tlscheck.TLSCheckResult{}},
		Workers:            1,
		ManagerCtx:         context.Background(),
		checkTimeout:       100 * time.Millisecond,
		MaxHistoryEntries:  1,
		ScanWindowStart:    start,
		ScanWindowEnd:      end,
		ScanWindowTimezone: tz,
	}
	return r, podListCalls
}

// waitInitialScan blocks until r.InitialScanDone is true or the test times out.
func waitInitialScan(t *testing.T, r *EndpointReconciler) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !r.InitialScanDone.Load() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for InitialScanDone")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// inactiveWindow returns a 1-hour scan window centred 12 hours from now, which
// is definitively inactive at the time any test using it runs.
func inactiveWindow() (start, end string) {
	futureHour := (time.Now().UTC().Hour() + 12) % 24
	return fmt.Sprintf("%02d:00", futureHour), fmt.Sprintf("%02d:00", (futureHour+1)%24)
}

// TestStartPeriodicScan_InsideWindow verifies that when the scan window covers
// the current time, ticker-triggered scan cycles run after the initial scan.
func TestStartPeriodicScan_InsideWindow(t *testing.T) {
	// "00:00"–"23:59" covers the full day; the current time is always inside.
	r, podListCalls := newWindowedReconciler(t, "00:00", "23:59", "UTC")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.StartPeriodicScan(ctx, 30*time.Millisecond, nil)
	waitInitialScan(t, r)
	countAfterInitial := podListCalls.Load()

	// Wait for at least one additional tick-triggered scan cycle.
	deadline := time.After(2 * time.Second)
	for {
		if podListCalls.Load() > countAfterInitial {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("no additional scan ran inside the scan window (pod list calls: %d)", podListCalls.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestStartPeriodicScan_OutsideWindow verifies that ticker-triggered scan cycles
// are skipped when the scan window does not cover the current time.
func TestStartPeriodicScan_OutsideWindow(t *testing.T) {
	start, end := inactiveWindow()
	r, podListCalls := newWindowedReconciler(t, start, end, "UTC")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.StartPeriodicScan(ctx, 30*time.Millisecond, nil)
	waitInitialScan(t, r)
	countAfterInitial := podListCalls.Load()

	// Allow 5+ ticks to fire — all should be skipped outside the window.
	time.Sleep(200 * time.Millisecond)
	if got := podListCalls.Load(); got != countAfterInitial {
		t.Errorf("expected no scans outside window, but %d extra pod list call(s) occurred", got-countAfterInitial)
	}
}

// TestStartPeriodicScan_InitialScanBypassesWindow verifies that the initial scan
// runs unconditionally even when the scan window is currently inactive.
func TestStartPeriodicScan_InitialScanBypassesWindow(t *testing.T) {
	start, end := inactiveWindow()
	r, _ := newWindowedReconciler(t, start, end, "UTC")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Long ticker interval ensures no tick fires during the test.
	r.StartPeriodicScan(ctx, time.Hour, nil)
	waitInitialScan(t, r)
}
