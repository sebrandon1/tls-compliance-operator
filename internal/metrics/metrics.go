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

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

const (
	// MetricsNamespace is the namespace for all tls_compliance metrics
	MetricsNamespace = "tls_compliance"

	ResultSuccess    = "success"
	ResultError      = "error"
	ErrorTypeProcess = "process"
)

var (
	// EndpointsTotal tracks total endpoints by compliance status
	EndpointsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{ //nolint:promlinter // renaming would break existing dashboards
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
		prometheus.GaugeOpts{ //nolint:promlinter // days is more user-friendly than seconds for cert expiry
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

	// ForwardSecrecy tracks whether all ciphers support forward secrecy per endpoint
	ForwardSecrecy = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "forward_secrecy",
			Help:      "Forward secrecy support (1=all ciphers use ephemeral key exchange, 0=not)",
		},
		[]string{"host", "port"},
	)

	// PQCReadiness tracks PQC readiness status per endpoint (1=current status, 0=not)
	PQCReadiness = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "pqc_readiness",
			Help:      "Post-quantum cryptography readiness (1=current status, 0=not)",
		},
		[]string{"host", "port", "readiness"},
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

	// ReconcileErrorsTotal tracks errors in resource-specific reconciliation handlers
	ReconcileErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_errors_total",
			Help:      "Total number of errors during resource reconciliation by source kind and error type",
		},
		[]string{"source_kind", "error_type"},
	)

	// ScanCycleErrorsTotal tracks the number of periodic scan cycle failures
	ScanCycleErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "scan_cycle_errors_total",
			Help:      "Total number of periodic scan cycle failures",
		},
	)

	// ScanCycleLastCompletedTimestamp records the Unix timestamp of the last successful periodic scan
	ScanCycleLastCompletedTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "scan_cycle_last_completed_timestamp",
			Help:      "Unix timestamp of the last completed periodic scan cycle",
		},
	)

	// CleanupCycleLastCompletedTimestamp records the Unix timestamp of the last successful cleanup
	CleanupCycleLastCompletedTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "cleanup_cycle_last_completed_timestamp",
			Help:      "Unix timestamp of the last completed cleanup cycle",
		},
	)

	// ReportsTTLDeletedTotal tracks reports deleted by retention policy
	ReportsTTLDeletedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reports_ttl_deleted_total",
			Help:      "Total number of TLSComplianceReports deleted by retention policy",
		},
	)

	FIPSModeEnabled = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "fips_mode_enabled",
			Help:      "Whether the cluster is running in FIPS mode (1=yes, 0=no)",
		},
	)

	// WorkerPoolInUse tracks the number of worker pool slots currently in use
	WorkerPoolInUse = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "worker_pool_in_use",
			Help:      "Number of worker pool slots currently in use",
		},
	)

	// EndpointsDiscoveredTotal tracks the total number of endpoints discovered
	EndpointsDiscoveredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "endpoints_discovered_total",
			Help:      "Total number of endpoints discovered",
		},
		[]string{"source_kind", "namespace"},
	)

	// ReconcileLatencySeconds tracks reconciliation latency by resource type
	ReconcileLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_latency_seconds",
			Help:      "End-to-end reconciliation latency from event receipt to completion, in seconds",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0},
		},
		[]string{"source_kind"},
	)

	// ReconcileInFlight tracks the number of reconciliations currently in progress
	ReconcileInFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_in_flight",
			Help:      "Number of reconciliations currently in progress",
		},
	)

	// ReconcileByResourceTotal tracks reconciliation attempts by resource type and result
	ReconcileByResourceTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_by_resource_total",
			Help:      "Total reconciliation attempts by resource type and result",
		},
		[]string{"source_kind", "result"},
	)

	// CheckErrorsTotal tracks TLS check errors by failure reason
	CheckErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "check_errors_total",
			Help:      "Total number of TLS check errors by failure reason",
		},
		[]string{"reason"},
	)

	// CircuitOpenSkippedTotal tracks TLS checks skipped because the endpoint circuit is open
	CircuitOpenSkippedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "circuit_open_skipped_total",
			Help:      "Total number of TLS checks skipped because the endpoint circuit breaker is open",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		EndpointsTotal,
		CheckDurationSeconds,
		CertificateExpiryDays,
		VersionSupport,
		ForwardSecrecy,
		PQCReadiness,
		ReconcileTotal,
		ScanCycleDurationSeconds,
		ScanCycleErrorsTotal,
		CheckRetriesTotal,
		CheckRetriesExhaustedTotal,
		ReconcileErrorsTotal,
		ScanCycleLastCompletedTimestamp,
		CleanupCycleLastCompletedTimestamp,
		ReportsTTLDeletedTotal,
		FIPSModeEnabled,
		WorkerPoolInUse,
		EndpointsDiscoveredTotal,
		ReconcileLatencySeconds,
		ReconcileInFlight,
		ReconcileByResourceTotal,
		CheckErrorsTotal,
		CircuitOpenSkippedTotal,
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

// RecordForwardSecrecy records whether all ciphers support forward secrecy
func RecordForwardSecrecy(host, port string, supported bool) {
	val := float64(0)
	if supported {
		val = 1
	}
	ForwardSecrecy.WithLabelValues(host, port).Set(val)
}

// RecordVersionSupport records whether a TLS version is supported
func RecordVersionSupport(host, port, version string, supported bool) {
	val := float64(0)
	if supported {
		val = 1
	}
	VersionSupport.WithLabelValues(host, port, version).Set(val)
}

// RecordPQCReadiness records the PQC readiness status for an endpoint.
// Sets the given readiness level to 1 and all others to 0.
func RecordPQCReadiness(host, port string, readiness securityv1alpha1.PQCReadiness) {
	for _, level := range []securityv1alpha1.PQCReadiness{
		securityv1alpha1.PQCReadinessPQCReady,
		securityv1alpha1.PQCReadinessTLS13Capable,
		securityv1alpha1.PQCReadinessLegacyTLS,
		securityv1alpha1.PQCReadinessNoPQC,
	} {
		val := float64(0)
		if level == readiness {
			val = 1
		}
		PQCReadiness.WithLabelValues(host, port, string(level)).Set(val)
	}
}

// RecordScanCycleDuration records the duration of a full scan cycle
func RecordScanCycleDuration(durationSeconds float64) {
	ScanCycleDurationSeconds.Observe(durationSeconds)
}

// RecordScanCycleError records a periodic scan cycle failure
func RecordScanCycleError() {
	ScanCycleErrorsTotal.Inc()
}

// RecordRetry records a TLS check retry attempt with the given failure reason
func RecordRetry(reason string) {
	CheckRetriesTotal.WithLabelValues(reason).Inc()
}

// RecordRetriesExhausted records that retries were exhausted for a TLS check
func RecordRetriesExhausted() {
	CheckRetriesExhaustedTotal.Inc()
}

// RecordReconcileError records an error during resource reconciliation
func RecordReconcileError(sourceKind, errorType string) {
	ReconcileErrorsTotal.WithLabelValues(sourceKind, errorType).Inc()
}

// RecordScanCycleCompleted sets the scan cycle timestamp to the current time
func RecordScanCycleCompleted() {
	ScanCycleLastCompletedTimestamp.SetToCurrentTime()
}

// RecordCleanupCycleCompleted sets the cleanup cycle timestamp to the current time
func RecordCleanupCycleCompleted() {
	CleanupCycleLastCompletedTimestamp.SetToCurrentTime()
}

// DeleteEndpointMetrics removes all per-endpoint metric label sets for a host:port
// to prevent stale time series from accumulating.
func DeleteEndpointMetrics(host, port string) {
	CertificateExpiryDays.DeleteLabelValues(host, port)
	ForwardSecrecy.DeleteLabelValues(host, port)
	for _, version := range []string{"ssl3.0", "1.0", "1.1", "1.2", "1.3"} {
		VersionSupport.DeleteLabelValues(host, port, version)
	}
	for _, level := range []string{"PQCReady", "TLS13Capable", "LegacyTLS", "NoPQC"} {
		PQCReadiness.DeleteLabelValues(host, port, level)
	}
}

// RecordReportTTLDeleted records a report deleted by the retention policy
func RecordReportTTLDeleted() {
	ReportsTTLDeletedTotal.Inc()
}

// RecordFIPSMode records whether the cluster is running in FIPS mode
func RecordFIPSMode(enabled bool) {
	val := float64(0)
	if enabled {
		val = 1
	}
	FIPSModeEnabled.Set(val)
}

// RecordWorkerAcquire increments the worker pool in-use gauge
func RecordWorkerAcquire() {
	WorkerPoolInUse.Inc()
}

// RecordWorkerRelease decrements the worker pool in-use gauge
func RecordWorkerRelease() {
	WorkerPoolInUse.Dec()
}

// RecordEndpointDiscovered increments the endpoint discovery counter
func RecordEndpointDiscovered(sourceKind, namespace string) {
	EndpointsDiscoveredTotal.WithLabelValues(sourceKind, namespace).Inc()
}

// RecordReconcileLatency records reconciliation latency for a resource type
func RecordReconcileLatency(sourceKind string, durationSeconds float64) {
	ReconcileLatencySeconds.WithLabelValues(sourceKind).Observe(durationSeconds)
}

// RecordReconcileInFlightInc increments the in-flight reconciliation gauge
func RecordReconcileInFlightInc() {
	ReconcileInFlight.Inc()
}

// RecordReconcileInFlightDec decrements the in-flight reconciliation gauge
func RecordReconcileInFlightDec() {
	ReconcileInFlight.Dec()
}

// RecordReconcileByResource records a reconciliation attempt by resource type and result
func RecordReconcileByResource(sourceKind, result string) {
	ReconcileByResourceTotal.WithLabelValues(sourceKind, result).Inc()
}

// RecordReconcileSuccess records a successful reconciliation for both the aggregate
// and per-resource counters.
func RecordReconcileSuccess(sourceKind string) {
	ReconcileTotal.WithLabelValues(ResultSuccess).Inc()
	ReconcileByResourceTotal.WithLabelValues(sourceKind, ResultSuccess).Inc()
}

// RecordCheckError records a TLS check error by failure reason
func RecordCheckError(reason string) {
	CheckErrorsTotal.WithLabelValues(reason).Inc()
}

// RecordCircuitOpenSkipped records a TLS check skipped because the circuit is open
func RecordCircuitOpenSkipped() {
	CircuitOpenSkippedTotal.Inc()
}
