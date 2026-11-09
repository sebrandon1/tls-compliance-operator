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

// Package notify delivers compliance status changes to external webhook
// endpoints. Delivery is best effort: a webhook that is down must never block
// or fail a scan.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
)

// Event is the JSON payload posted to each webhook.
type Event struct {
	ReportName string    `json:"reportName"`
	Namespace  string    `json:"namespace,omitempty"`
	Host       string    `json:"host"`
	Port       int32     `json:"port"`
	OldStatus  string    `json:"oldStatus"`
	NewStatus  string    `json:"newStatus"`
	OldPQC     string    `json:"oldPQCReadiness,omitempty"`
	NewPQC     string    `json:"newPQCReadiness,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// Notifier posts Events to a fixed set of URLs.
type Notifier struct {
	URLs    []string
	Timeout time.Duration
	// Retries is the number of extra attempts after the first failure.
	Retries int
	client  *http.Client
}

// NewNotifier returns a Notifier for urls. A non-positive timeout selects the
// default of five seconds.
func NewNotifier(urls []string, timeout time.Duration, retries int) *Notifier {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if retries < 0 {
		retries = 0
	}
	return &Notifier{
		URLs:    urls,
		Timeout: timeout,
		Retries: retries,
		client:  &http.Client{Timeout: timeout},
	}
}

// Deliver posts event to every configured URL, retrying each failure with
// linear backoff. It returns the number of URLs that accepted the event. The
// caller decides whether to run it in the background; it never returns an
// error because delivery failures are logged and counted, not propagated.
func (n *Notifier) Deliver(ctx context.Context, logger logr.Logger, event *Event) int {
	if n == nil || len(n.URLs) == 0 {
		return 0
	}

	payload, err := json.Marshal(*event)
	if err != nil {
		logger.Error(err, "failed to encode webhook payload", "report", event.ReportName)
		metrics.RecordNotification(metrics.NotificationError)
		return 0
	}

	var delivered int
	for _, url := range n.URLs {
		if n.deliverOne(ctx, logger, url, payload, event.ReportName) {
			delivered++
			metrics.RecordNotification(metrics.NotificationSuccess)
			continue
		}
		metrics.RecordNotification(metrics.NotificationError)
	}
	return delivered
}

func (n *Notifier) deliverOne(ctx context.Context, logger logr.Logger, url string, payload []byte, reportName string) bool {
	for attempt := 0; attempt <= n.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}

		attemptCtx, cancel := context.WithTimeout(ctx, n.Timeout)
		err := n.post(attemptCtx, url, payload)
		cancel()
		if err == nil {
			return true
		}
		logger.V(1).Info("webhook delivery failed", "url", url, "report", reportName, "attempt", attempt+1, "error", err.Error())
	}

	logger.Error(nil, "webhook delivery exhausted retries", "url", url, "report", reportName, "retries", n.Retries)
	return false
}

func (n *Notifier) post(ctx context.Context, url string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}
