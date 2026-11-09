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

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/policy"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlsprofile"
)

func compilePolicy(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	result, err := policy.Compile([]byte(doc))
	if err != nil {
		t.Fatalf("policy.Compile() error = %v", err)
	}
	return result.Policy
}

func policyReport(namespace, name string) *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "rpt"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "10.0.0.1", Port: 443,
			SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: namespace, SourceName: name,
		},
	}
}

func TestApplyPolicy_Exempt(t *testing.T) {
	r := &EndpointReconciler{Policy: compilePolicy(t, `
rules:
  - namespace: "^openshift-e2e-loki$"
    profile: exempt
`)}
	cr := policyReport("openshift-e2e-loki", "loki")

	r.applyPolicy(cr)
	if !cr.Status.Exempt {
		t.Error("Exempt = false, want true")
	}
	if cr.Status.PolicyProfile != string(policy.ProfileExempt) {
		t.Errorf("PolicyProfile = %q, want exempt", cr.Status.PolicyProfile)
	}
	if cr.Status.ExemptReason == "" {
		t.Error("ExemptReason = empty, want a reason")
	}
}

func TestApplyPolicy_SelectedComponent(t *testing.T) {
	r := &EndpointReconciler{Policy: compilePolicy(t, `
rules:
  - namespace: "^openshift-ingress$"
    profile: ingress
`)}
	cr := policyReport("openshift-ingress", "router")

	r.applyPolicy(cr)
	if cr.Status.Exempt {
		t.Error("Exempt = true, want false")
	}
	if cr.Status.PolicyProfile != string(policy.ProfileIngress) {
		t.Errorf("PolicyProfile = %q, want ingress", cr.Status.PolicyProfile)
	}
}

func TestApplyPolicy_NilPolicyLeavesFieldsEmpty(t *testing.T) {
	r := &EndpointReconciler{}
	cr := policyReport("default", "svc")

	r.applyPolicy(cr)
	if cr.Status.PolicyProfile != "" || cr.Status.Exempt {
		t.Errorf("policy fields = %q/%v, want empty", cr.Status.PolicyProfile, cr.Status.Exempt)
	}
}

func profileFetcherForTest(t *testing.T) *tlsprofile.Fetcher {
	t.Helper()
	fetcher, err := tlsprofile.NewStaticFetcher(tlsprofile.ProfileTypeIntermediate)
	if err != nil {
		t.Fatalf("NewStaticFetcher() error = %v", err)
	}
	return fetcher
}

func TestUpdateConditions_ExemptSetsProfileConditionTrue(t *testing.T) {
	r := &EndpointReconciler{ProfileFetcher: profileFetcherForTest(t)}
	cr := policyReport("openshift-e2e-loki", "loki")
	cr.Status.Exempt = true
	cr.Status.ExemptReason = "policy"

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, &tlscheck.TLSCheckResult{SupportsTLS12: true})

	condition := apimeta.FindStatusCondition(cr.Status.Conditions, "TLSProfileCompliant")
	if condition == nil {
		t.Fatal("TLSProfileCompliant condition missing")
	}
	if condition.Status != metav1.ConditionTrue || condition.Reason != "Exempt" {
		t.Errorf("condition = %s/%s, want True/Exempt", condition.Status, condition.Reason)
	}
}

func TestUpdateConditions_PolicySelectsOneComponent(t *testing.T) {
	r := &EndpointReconciler{
		ProfileFetcher: profileFetcherForTest(t),
		Policy:         compilePolicy(t, "rules:\n  - namespace: \"^openshift-ingress$\"\n    profile: ingress\n"),
	}
	cr := policyReport("openshift-ingress", "router")
	cr.Status.PolicyProfile = string(policy.ProfileIngress)
	// Ingress compliant, APIServer not: the policy makes the ingress result the
	// one that counts.
	cr.Status.IngressProfileCompliance = &securityv1alpha1.TLSProfileComplianceResult{Compliant: true}
	cr.Status.APIServerProfileCompliance = &securityv1alpha1.TLSProfileComplianceResult{Compliant: false}

	r.updateConditions(cr, securityv1alpha1.ComplianceStatusCompliant, &tlscheck.TLSCheckResult{SupportsTLS12: true})

	condition := apimeta.FindStatusCondition(cr.Status.Conditions, "TLSProfileCompliant")
	if condition == nil {
		t.Fatal("TLSProfileCompliant condition missing")
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("condition = %s/%s, want True because the selected ingress profile is compliant", condition.Status, condition.Reason)
	}
}

func TestCheckProfileCompliance_PopulatesComponents(t *testing.T) {
	r := &EndpointReconciler{ProfileFetcher: profileFetcherForTest(t)}
	cr := policyReport("default", "svc")

	r.checkProfileCompliance(context.Background(), cr, &tlscheck.TLSCheckResult{SupportsTLS12: true, SupportsTLS13: true})

	if cr.Status.APIServerProfileCompliance == nil {
		t.Error("APIServerProfileCompliance = nil, want a result")
	}
	if cr.Status.IngressProfileCompliance == nil {
		t.Error("IngressProfileCompliance = nil, want a result")
	}
	if cr.Status.KubeletProfileCompliance == nil {
		t.Error("KubeletProfileCompliance = nil, want a result")
	}
}

func TestProfileResultFor_SelectsComponent(t *testing.T) {
	cr := &securityv1alpha1.TLSComplianceReport{}
	cr.Status.KubeletProfileCompliance = &securityv1alpha1.TLSProfileComplianceResult{ProfileType: "kubelet"}
	cr.Status.IngressProfileCompliance = &securityv1alpha1.TLSProfileComplianceResult{ProfileType: "ingress"}
	cr.Status.APIServerProfileCompliance = &securityv1alpha1.TLSProfileComplianceResult{ProfileType: "apiserver"}

	if got := profileResultFor(cr, "kubelet"); got == nil || got.ProfileType != "kubelet" {
		t.Errorf("profileResultFor(kubelet) = %+v", got)
	}
	if got := profileResultFor(cr, "ingress"); got == nil || got.ProfileType != "ingress" {
		t.Errorf("profileResultFor(ingress) = %+v", got)
	}
	if got := profileResultFor(cr, "unknown"); got == nil || got.ProfileType != "apiserver" {
		t.Errorf("profileResultFor(unknown) = %+v, want the apiserver default", got)
	}
}
