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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// --- helpers ---

func gaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	_ = g.Write(m)
	return m.GetGauge().GetValue()
}

func counterValue(c prometheus.Counter) float64 {
	m := &dto.Metric{}
	_ = c.(prometheus.Metric).Write(m)
	return m.GetCounter().GetValue()
}

func gaugeVecValue(gv *prometheus.GaugeVec, labels ...string) float64 {
	g, _ := gv.GetMetricWithLabelValues(labels...)
	return gaugeValue(g)
}

func counterVecValue(cv *prometheus.CounterVec, labels ...string) float64 {
	c, _ := cv.GetMetricWithLabelValues(labels...)
	return counterValue(c)
}

func histogramCount(h prometheus.Histogram) uint64 {
	m := &dto.Metric{}
	_ = h.(prometheus.Metric).Write(m)
	return m.GetHistogram().GetSampleCount()
}

func histogramVecCount(hv *prometheus.HistogramVec, labels ...string) uint64 {
	h, _ := hv.GetMetricWithLabelValues(labels...)
	m := &dto.Metric{}
	_ = h.(prometheus.Metric).Write(m)
	return m.GetHistogram().GetSampleCount()
}

func assertTimestampGaugeSetToNow(t *testing.T, recordFn func(), gauge prometheus.Gauge) {
	t.Helper()
	before := float64(time.Now().Unix())
	recordFn()
	after := float64(time.Now().Unix()) + 1

	val := gaugeValue(gauge)
	if val < before || val > after {
		t.Errorf("expected timestamp between %v and %v, got %v", before, after, val)
	}
}

func assertCounterInc(t *testing.T, c prometheus.Counter, fn func()) {
	t.Helper()
	before := counterValue(c)
	fn()
	after := counterValue(c)
	if after != before+1 {
		t.Errorf("expected counter to increment by 1, got %v -> %v", before, after)
	}
}

// --- tests ---

func TestRecordScanCycleCompleted(t *testing.T) {
	assertTimestampGaugeSetToNow(t, RecordScanCycleCompleted, ScanCycleLastCompletedTimestamp)
}

func TestRecordCleanupCycleCompleted(t *testing.T) {
	assertTimestampGaugeSetToNow(t, RecordCleanupCycleCompleted, CleanupCycleLastCompletedTimestamp)
}

func TestRecordFIPSMode(t *testing.T) {
	RecordFIPSMode(true)
	if v := gaugeValue(FIPSModeEnabled); v != 1 {
		t.Errorf("expected FIPS gauge 1, got %v", v)
	}

	RecordFIPSMode(false)
	if v := gaugeValue(FIPSModeEnabled); v != 0 {
		t.Errorf("expected FIPS gauge 0, got %v", v)
	}
}

func TestRecordReconcile(t *testing.T) {
	assertCounterInc(t, ReconcileTotal.WithLabelValues(ResultSuccess), func() {
		RecordReconcile(ResultSuccess)
	})
}

func TestRecordReconcileSuccess(t *testing.T) {
	beforeTotal := counterVecValue(ReconcileTotal, ResultSuccess)
	beforeByResource := counterVecValue(ReconcileByResourceTotal, "Service", ResultSuccess)
	RecordReconcileSuccess("Service")
	afterTotal := counterVecValue(ReconcileTotal, ResultSuccess)
	afterByResource := counterVecValue(ReconcileByResourceTotal, "Service", ResultSuccess)
	if afterTotal != beforeTotal+1 {
		t.Errorf("expected ReconcileTotal to increment by 1, got %v -> %v", beforeTotal, afterTotal)
	}
	if afterByResource != beforeByResource+1 {
		t.Errorf("expected ReconcileByResourceTotal to increment by 1, got %v -> %v", beforeByResource, afterByResource)
	}
}

func TestRecordCheckDuration(t *testing.T) {
	before := histogramCount(CheckDurationSeconds)
	RecordCheckDuration(1.5)
	after := histogramCount(CheckDurationSeconds)
	if after != before+1 {
		t.Errorf("expected histogram sample count to increment by 1, got %v -> %v", before, after)
	}
}

func TestRecordCertExpiry(t *testing.T) {
	RecordCertExpiry("example.com", "443", 30)
	if v := gaugeVecValue(CertificateExpiryDays, "example.com", "443"); v != 30 {
		t.Errorf("expected 30, got %v", v)
	}
}

func TestRecordForwardSecrecy(t *testing.T) {
	RecordForwardSecrecy("host", "443", true)
	if v := gaugeVecValue(ForwardSecrecy, "host", "443"); v != 1 {
		t.Errorf("expected 1, got %v", v)
	}
	RecordForwardSecrecy("host", "443", false)
	if v := gaugeVecValue(ForwardSecrecy, "host", "443"); v != 0 {
		t.Errorf("expected 0, got %v", v)
	}
}

func TestRecordVersionSupport(t *testing.T) {
	RecordVersionSupport("host", "443", "1.3", true)
	if v := gaugeVecValue(VersionSupport, "host", "443", "1.3"); v != 1 {
		t.Errorf("expected 1, got %v", v)
	}
	RecordVersionSupport("host", "443", "1.3", false)
	if v := gaugeVecValue(VersionSupport, "host", "443", "1.3"); v != 0 {
		t.Errorf("expected 0, got %v", v)
	}
}

func TestRecordPQCReadiness(t *testing.T) {
	RecordPQCReadiness("host", "443", securityv1alpha1.PQCReadinessPQCReady)
	if v := gaugeVecValue(PQCReadiness, "host", "443", string(securityv1alpha1.PQCReadinessPQCReady)); v != 1 {
		t.Errorf("expected PQCReady=1, got %v", v)
	}
	if v := gaugeVecValue(PQCReadiness, "host", "443", string(securityv1alpha1.PQCReadinessNoPQC)); v != 0 {
		t.Errorf("expected NoPQC=0, got %v", v)
	}
}

func TestRecordScanCycleError(t *testing.T) {
	assertCounterInc(t, ScanCycleErrorsTotal, func() {
		RecordScanCycleError()
	})
}

func TestRecordScanCycleDuration(t *testing.T) {
	before := histogramCount(ScanCycleDurationSeconds)
	RecordScanCycleDuration(120.5)
	after := histogramCount(ScanCycleDurationSeconds)
	if after != before+1 {
		t.Errorf("expected histogram sample count to increment by 1, got %v -> %v", before, after)
	}
}

func TestRecordRetry(t *testing.T) {
	assertCounterInc(t, CheckRetriesTotal.WithLabelValues("timeout"), func() {
		RecordRetry("timeout")
	})
}

func TestRecordRetriesExhausted(t *testing.T) {
	assertCounterInc(t, CheckRetriesExhaustedTotal, func() {
		RecordRetriesExhausted()
	})
}

func TestRecordReconcileError(t *testing.T) {
	assertCounterInc(t, ReconcileErrorsTotal.WithLabelValues("Service", ErrorTypeProcess), func() {
		RecordReconcileError("Service", ErrorTypeProcess)
	})
}

func TestDeleteEndpointMetrics(t *testing.T) {
	RecordCertExpiry("del-host", "8443", 90)
	RecordForwardSecrecy("del-host", "8443", true)
	RecordVersionSupport("del-host", "8443", "1.3", true)
	RecordPQCReadiness("del-host", "8443", securityv1alpha1.PQCReadinessPQCReady)

	DeleteEndpointMetrics("del-host", "8443")

	// After deletion, GetMetricWithLabelValues returns a fresh zero-value gauge.
	if v := gaugeVecValue(CertificateExpiryDays, "del-host", "8443"); v != 0 {
		t.Errorf("expected CertificateExpiryDays=0 after delete, got %v", v)
	}
	if v := gaugeVecValue(ForwardSecrecy, "del-host", "8443"); v != 0 {
		t.Errorf("expected ForwardSecrecy=0 after delete, got %v", v)
	}
	if v := gaugeVecValue(VersionSupport, "del-host", "8443", "1.3"); v != 0 {
		t.Errorf("expected VersionSupport=0 after delete, got %v", v)
	}
	if v := gaugeVecValue(PQCReadiness, "del-host", "8443", string(securityv1alpha1.PQCReadinessPQCReady)); v != 0 {
		t.Errorf("expected PQCReadiness=0 after delete, got %v", v)
	}
}

func TestRecordReportTTLDeleted(t *testing.T) {
	assertCounterInc(t, ReportsTTLDeletedTotal, func() {
		RecordReportTTLDeleted()
	})
}

func TestRecordWorkerAcquireRelease(t *testing.T) {
	WorkerPoolInUse.Set(0)
	RecordWorkerAcquire()
	if v := gaugeValue(WorkerPoolInUse); v != 1 {
		t.Errorf("expected 1 after acquire, got %v", v)
	}
	RecordWorkerAcquire()
	if v := gaugeValue(WorkerPoolInUse); v != 2 {
		t.Errorf("expected 2 after second acquire, got %v", v)
	}
	RecordWorkerRelease()
	if v := gaugeValue(WorkerPoolInUse); v != 1 {
		t.Errorf("expected 1 after release, got %v", v)
	}
	RecordWorkerRelease()
	if v := gaugeValue(WorkerPoolInUse); v != 0 {
		t.Errorf("expected 0 after second release, got %v", v)
	}
}

func TestRecordEndpointDiscovered(t *testing.T) {
	before := counterVecValue(EndpointsDiscoveredTotal, "Service", "default")
	RecordEndpointDiscovered("Service", "default")
	after := counterVecValue(EndpointsDiscoveredTotal, "Service", "default")
	if after != before+1 {
		t.Errorf("expected counter to increment by 1, got %v -> %v", before, after)
	}
}

func TestRecordReconcileLatency(t *testing.T) {
	before := histogramVecCount(ReconcileLatencySeconds, "Service")
	RecordReconcileLatency("Service", 0.5)
	after := histogramVecCount(ReconcileLatencySeconds, "Service")
	if after != before+1 {
		t.Errorf("expected histogram sample count to increment by 1, got %v -> %v", before, after)
	}
}

func TestRecordReconcileInFlight(t *testing.T) {
	ReconcileInFlight.Set(0)
	RecordReconcileInFlightInc()
	if v := gaugeValue(ReconcileInFlight); v != 1 {
		t.Errorf("expected 1, got %v", v)
	}
	RecordReconcileInFlightDec()
	if v := gaugeValue(ReconcileInFlight); v != 0 {
		t.Errorf("expected 0, got %v", v)
	}
}

func TestRecordReconcileByResource(t *testing.T) {
	before := counterVecValue(ReconcileByResourceTotal, "Ingress", "success")
	RecordReconcileByResource("Ingress", "success")
	after := counterVecValue(ReconcileByResourceTotal, "Ingress", "success")
	if after != before+1 {
		t.Errorf("expected counter to increment by 1, got %v -> %v", before, after)
	}
}

func TestRecordCheckError(t *testing.T) {
	before := counterVecValue(CheckErrorsTotal, "Timeout")
	RecordCheckError("Timeout")
	after := counterVecValue(CheckErrorsTotal, "Timeout")
	if after != before+1 {
		t.Errorf("expected counter to increment by 1, got %v -> %v", before, after)
	}
}

func TestRecordCircuitOpenSkipped(t *testing.T) {
	assertCounterInc(t, CircuitOpenSkippedTotal, RecordCircuitOpenSkipped)
}
