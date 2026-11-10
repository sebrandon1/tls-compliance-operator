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

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

// isProbeUnreachable reports whether a failure reason is a reachability
// failure that a loopback-only listener explains.
func isProbeUnreachable(reason tlscheck.FailureReason) bool {
	switch reason {
	// An empty reason means the checker reported a failure without classifying
	// it; the endpoint was still not reachable.
	case tlscheck.FailureReasonNone,
		tlscheck.FailureReasonClosed,
		tlscheck.FailureReasonTimeout,
		tlscheck.FailureReasonUnreachable:
		return true
	default:
		return false
	}
}

// isLoopbackOnlyReport reports whether the report's persisted bind addresses
// are all loopback. It returns false when listening-port discovery is disabled,
// so reports keep their pre-existing classification after an operator restart
// without the flag.
func (r *EndpointReconciler) isLoopbackOnlyReport(ctx context.Context, crName string) bool {
	if !r.DiscoverListeningPorts || (r.APIReader == nil && r.Client == nil) {
		return false
	}
	var cr securityv1alpha1.TLSComplianceReport
	if err := r.apiReader().Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		return false
	}
	return endpoint.IsLoopbackOnly(cr.Status.ListenAddresses)
}
