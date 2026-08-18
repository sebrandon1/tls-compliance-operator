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
	"time"

	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

const (
	circuitBreakerThreshold = 3
	circuitBreakerCooldown  = 15 * time.Minute
)

type circuitState struct {
	failures     int
	nextEligible time.Time
}

func isCircuitFailure(reason tlscheck.FailureReason) bool {
	return reason == tlscheck.FailureReasonTimeout || reason == tlscheck.FailureReasonUnreachable
}

func (r *EndpointReconciler) skipIfCircuitOpen(crName string) bool {
	if !r.circuitOpen(crName) {
		return false
	}
	metrics.RecordCircuitOpenSkipped()
	return true
}

func (r *EndpointReconciler) circuitOpen(crName string) bool {
	r.circuitMu.Lock()
	defer r.circuitMu.Unlock()
	st, ok := r.circuits[crName]
	if !ok {
		return false
	}
	return time.Now().Before(st.nextEligible)
}

func (r *EndpointReconciler) recordCircuitFailure(crName string) {
	r.circuitMu.Lock()
	defer r.circuitMu.Unlock()
	if r.circuits == nil {
		r.circuits = make(map[string]circuitState)
	}
	st := r.circuits[crName]
	st.failures++
	if st.failures >= circuitBreakerThreshold {
		st.nextEligible = time.Now().Add(circuitBreakerCooldown)
	}
	r.circuits[crName] = st
}

func (r *EndpointReconciler) recordCircuitSuccess(crName string) {
	r.circuitMu.Lock()
	defer r.circuitMu.Unlock()
	delete(r.circuits, crName)
}
