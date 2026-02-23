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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// MetricsNamespace is the namespace for all tls_compliance metrics
	MetricsNamespace = "tls_compliance"
)

var (
	// EndpointsTotal tracks total endpoints by compliance status
	EndpointsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "endpoints_total",
			Help:      "Total number of endpoints by compliance status",
		},
		[]string{"status"},
	)

	// CheckDurationSeconds tracks TLS check duration
	CheckDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "check_duration_seconds",
			Help:      "Duration of TLS endpoint checks in seconds",
			Buckets:   []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0},
		},
	)

	// CertificateExpiryDays tracks days until certificate expiry
	CertificateExpiryDays = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "certificate_expiry_days",
			Help:      "Number of days until certificate expiry",
		},
		[]string{"host", "port"},
	)

	// VersionSupport tracks TLS version support per endpoint
	VersionSupport = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "version_support",
			Help:      "TLS version support (1=supported, 0=not supported)",
		},
		[]string{"host", "port", "version"},
	)

	// ReconcileTotal tracks reconciliation attempts
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_total",
			Help:      "Total number of reconciliation attempts",
		},
		[]string{"result"},
	)

	// ScanCycleDurationSeconds tracks full scan cycle duration
	ScanCycleDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "scan_cycle_duration_seconds",
			Help:      "Duration of full scan cycles in seconds",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600},
		},
	)

	// CheckRetriesTotal tracks the number of TLS check retry attempts
	CheckRetriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "check_retries_total",
			Help:      "Total number of TLS check retry attempts",
		},
		[]string{"reason"},
	)

	// CheckRetriesExhaustedTotal tracks how many times retries were exhausted
	CheckRetriesExhaustedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "check_retries_exhausted_total",
			Help:      "Total number of times TLS check retries were exhausted",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		EndpointsTotal,
		CheckDurationSeconds,
		CertificateExpiryDays,
		VersionSupport,
		ReconcileTotal,
		ScanCycleDurationSeconds,
		CheckRetriesTotal,
		CheckRetriesExhaustedTotal,
	)
}

// RecordReconcile records a reconciliation result
func RecordReconcile(result string) {
	ReconcileTotal.WithLabelValues(result).Inc()
}

// RecordCheckDuration records the duration of a TLS check
func RecordCheckDuration(durationSeconds float64) {
	CheckDurationSeconds.Observe(durationSeconds)
}

// RecordCertExpiry records the days until certificate expiry
func RecordCertExpiry(host, port string, days float64) {
	CertificateExpiryDays.WithLabelValues(host, port).Set(days)
}

// RecordVersionSupport records whether a TLS version is supported
func RecordVersionSupport(host, port, version string, supported bool) {
	val := float64(0)
	if supported {
		val = 1
	}
	VersionSupport.WithLabelValues(host, port, version).Set(val)
}

// RecordScanCycleDuration records the duration of a full scan cycle
func RecordScanCycleDuration(durationSeconds float64) {
	ScanCycleDurationSeconds.Observe(durationSeconds)
}

// RecordRetry records a TLS check retry attempt with the given failure reason
func RecordRetry(reason string) {
	CheckRetriesTotal.WithLabelValues(reason).Inc()
}

// RecordRetriesExhausted records that retries were exhausted for a TLS check
func RecordRetriesExhausted() {
	CheckRetriesExhaustedTotal.Inc()
}
