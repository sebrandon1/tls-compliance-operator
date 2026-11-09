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
	"bytes"
	"context"
	"testing"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
)

func TestProcessEndpoint_DryRunWritesWithoutCreating(t *testing.T) {
	var buf bytes.Buffer
	r := &EndpointReconciler{DryRun: true, DryRunWriter: &buf}

	ep := &endpoint.Endpoint{
		Host:            "10.0.0.5",
		Port:            8443,
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "app-0",
	}
	if err := r.processEndpoint(context.Background(), ep); err != nil {
		t.Fatalf("processEndpoint() error = %v", err)
	}

	want := "Pod default/app-0 10.0.0.5:8443\n"
	if buf.String() != want {
		t.Errorf("dry-run output = %q, want %q", buf.String(), want)
	}
}
