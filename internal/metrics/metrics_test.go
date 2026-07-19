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
)

func gaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	_ = g.Write(m)
	return m.GetGauge().GetValue()
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
