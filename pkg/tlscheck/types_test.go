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

package tlscheck

import "testing"

func TestFailureReason_IsTransient(t *testing.T) {
	tests := []struct {
		reason   FailureReason
		expected bool
	}{
		{FailureReasonNone, false},
		{FailureReasonTimeout, true},
		{FailureReasonClosed, true},
		{FailureReasonUnreachable, true},
		{FailureReasonFiltered, true},
		{FailureReasonNoTLS, false},
		{FailureReasonMutualTLSRequired, false},
		{FailureReason("SomethingElse"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			got := tt.reason.IsTransient()
			if got != tt.expected {
				t.Errorf("FailureReason(%q).IsTransient() = %v, want %v", tt.reason, got, tt.expected)
			}
		})
	}
}
