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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlsprofile"
)

func customProfileReport() *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "rpt"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "svc",
		},
	}
}

func TestCheckProfileCompliance_CustomProfile(t *testing.T) {
	profile := tlsprofile.Profile{
		Type:          tlsprofile.ProfileTypeCustom,
		MinTLSVersion: tlsprofile.VersionTLS13,
	}
	r := &EndpointReconciler{CustomProfile: &profile}

	cr := customProfileReport()
	// TLS 1.2 only: the custom profile requires TLS 1.3.
	r.checkProfileCompliance(context.Background(), cr, &tlscheck.TLSCheckResult{SupportsTLS12: true})

	got := cr.Status.CustomProfileCompliance
	if got == nil {
		t.Fatal("CustomProfileCompliance = nil, want a result")
	}
	if got.ProfileType != string(tlsprofile.ProfileTypeCustom) {
		t.Errorf("ProfileType = %q, want %q", got.ProfileType, tlsprofile.ProfileTypeCustom)
	}
	if got.Compliant {
		t.Error("expected a TLS 1.2-only endpoint to be non-compliant with a TLS 1.3 minimum")
	}
	if got.MinTLSVersionMet {
		t.Error("expected MinTLSVersionMet to be false")
	}
}

func TestCheckProfileCompliance_CustomProfileCompliant(t *testing.T) {
	profile := tlsprofile.Profile{
		Type:          tlsprofile.ProfileTypeCustom,
		MinTLSVersion: tlsprofile.VersionTLS13,
	}
	r := &EndpointReconciler{CustomProfile: &profile}

	cr := customProfileReport()
	// Only TLS 1.3: no version below the profile's minimum is supported.
	r.checkProfileCompliance(context.Background(), cr, &tlscheck.TLSCheckResult{SupportsTLS13: true})

	if cr.Status.CustomProfileCompliance == nil || !cr.Status.CustomProfileCompliance.Compliant {
		t.Errorf("CustomProfileCompliance = %+v, want compliant", cr.Status.CustomProfileCompliance)
	}
	if !cr.Status.CustomProfileCompliance.MinTLSVersionMet {
		t.Error("expected MinTLSVersionMet to be true")
	}
}

func TestCheckProfileCompliance_NoCustomProfile(t *testing.T) {
	r := &EndpointReconciler{}
	cr := customProfileReport()
	r.checkProfileCompliance(context.Background(), cr, &tlscheck.TLSCheckResult{SupportsTLS13: true})

	if cr.Status.CustomProfileCompliance != nil {
		t.Errorf("CustomProfileCompliance = %+v, want nil", cr.Status.CustomProfileCompliance)
	}
}
