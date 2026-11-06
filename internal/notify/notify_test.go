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

package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
)

func counterVecValue(cv *prometheus.CounterVec, labels ...string) float64 {
	c, _ := cv.GetMetricWithLabelValues(labels...)
	m := &dto.Metric{}
	_ = c.Write(m)
	return m.GetCounter().GetValue()
}

func testEvent() *Event {
	return &Event{
		ReportName: "web-443-abcd1234",
		Namespace:  "prod",
		Host:       "web.example.com",
		Port:       443,
		OldStatus:  "Compliant",
		NewStatus:  "NonCompliant",
		Timestamp:  time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
	}
}

func TestDeliver_PostsJSONPayload(t *testing.T) {
	received := make(chan Event, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("invalid payload: %v", err)
		}
		received <- event
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewNotifier([]string{server.URL}, time.Second, 0)
	if got := n.Deliver(context.Background(), logr.Discard(), testEvent()); got != 1 {
		t.Fatalf("Deliver() = %d, want 1", got)
	}

	select {
	case event := <-received:
		if event.ReportName != "web-443-abcd1234" || event.Host != "web.example.com" {
			t.Errorf("unexpected event: %+v", event)
		}
		if event.OldStatus != "Compliant" || event.NewStatus != "NonCompliant" {
			t.Errorf("unexpected status transition: %+v", event)
		}
	default:
		t.Fatal("webhook was not called")
	}
}

func TestDeliver_RetriesUntilAccepted(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	n := NewNotifier([]string{server.URL}, time.Second, 1)
	if got := n.Deliver(context.Background(), logr.Discard(), testEvent()); got != 1 {
		t.Fatalf("Deliver() = %d, want 1", got)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestDeliver_ExhaustsRetries(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	n := NewNotifier([]string{server.URL}, time.Second, 1)
	if got := n.Deliver(context.Background(), logr.Discard(), testEvent()); got != 0 {
		t.Fatalf("Deliver() = %d, want 0", got)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2 (initial + 1 retry)", got)
	}
}

func TestDeliver_RecordsMetricsAndFansOut(t *testing.T) {
	hits := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	before := counterVecValue(metrics.NotificationsTotal, metrics.NotificationSuccess)
	n := NewNotifier([]string{server.URL, server.URL}, time.Second, 0)
	if got := n.Deliver(context.Background(), logr.Discard(), testEvent()); got != 2 {
		t.Fatalf("Deliver() = %d, want 2", got)
	}
	after := counterVecValue(metrics.NotificationsTotal, metrics.NotificationSuccess)
	if after-before != 2 {
		t.Errorf("success counter increased by %v, want 2", after-before)
	}
	if len(hits) != 2 {
		t.Errorf("server hit %d times, want 2", len(hits))
	}
}

func TestDeliver_NilNotifierIsNoop(t *testing.T) {
	var n *Notifier
	if got := n.Deliver(context.Background(), logr.Discard(), testEvent()); got != 0 {
		t.Errorf("Deliver() = %d, want 0", got)
	}

	empty := NewNotifier(nil, time.Second, 0)
	if got := empty.Deliver(context.Background(), logr.Discard(), testEvent()); got != 0 {
		t.Errorf("Deliver() with no URLs = %d, want 0", got)
	}
}

func TestNewNotifier_DefaultsAndClamps(t *testing.T) {
	n := NewNotifier([]string{"http://example.invalid/hook"}, 0, -3)
	if n.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want the 5s default", n.Timeout)
	}
	if n.Retries != 0 {
		t.Errorf("Retries = %d, want 0 for a negative value", n.Retries)
	}
}

func TestDeliver_CancelledContextStopsRetrying(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	n := NewNotifier([]string{"http://127.0.0.1:1/hook"}, time.Second, 3)
	if got := n.Deliver(ctx, logr.Discard(), testEvent()); got != 0 {
		t.Errorf("Deliver() = %d, want 0", got)
	}
}
