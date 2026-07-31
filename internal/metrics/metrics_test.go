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

func histogramCount(h prometheus.Histogram) uint64 {
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
	assertCounterInc(t, ReconcileTotal.WithLabelValues("success"), func() {
		RecordReconcile("success")
	})
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
	assertCounterInc(t, ReconcileErrorsTotal.WithLabelValues("Service", "process"), func() {
		RecordReconcileError("Service", "process")
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
