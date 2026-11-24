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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiversion "k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// failingDiscovery forces ServerVersion and resource lookups to fail.
type failingDiscovery struct {
	*fakediscovery.FakeDiscovery
}

func (f *failingDiscovery) ServerVersion() (*apiversion.Info, error) {
	return nil, errors.New("connection refused")
}

func (f *failingDiscovery) ServerResourcesForGroupVersion(string) (*metav1.APIResourceList, error) {
	return nil, errors.New("connection refused")
}

func healthyDiscovery() *fakediscovery.FakeDiscovery {
	d := &fakediscovery.FakeDiscovery{Fake: &k8stesting.Fake{}}
	d.FakedServerVersion = &apiversion.Info{GitVersion: "v1.35.9"}
	d.Resources = []*metav1.APIResourceList{{
		GroupVersion: securityv1alpha1.GroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "tlscompliancereports"},
			{Name: "tlscompliancetargets"},
		},
	}}
	return d
}

func TestCheckAPIServer(t *testing.T) {
	if got := checkAPIServer(doctorClients{discovery: healthyDiscovery()}); got.Status != doctorPass {
		t.Errorf("reachable API status = %s, want PASS", got.Status)
	}
	if got := checkAPIServer(doctorClients{discovery: &failingDiscovery{healthyDiscovery()}}); got.Status != doctorFail {
		t.Errorf("unreachable API status = %s, want FAIL", got.Status)
	}
}

func TestCheckCRDs(t *testing.T) {
	if got := checkCRDs(doctorClients{discovery: healthyDiscovery()}); got.Status != doctorPass {
		t.Errorf("installed CRDs status = %s, want PASS", got.Status)
	}
	partial := healthyDiscovery()
	partial.Resources[0].APIResources = partial.Resources[0].APIResources[:1]
	got := checkCRDs(doctorClients{discovery: partial})
	if got.Status != doctorFail || !strings.Contains(got.Message, "tlscompliancetargets") {
		t.Errorf("missing CRD result = %+v, want FAIL naming tlscompliancetargets", got)
	}
	if got := checkCRDs(doctorClients{discovery: &failingDiscovery{healthyDiscovery()}}); got.Status != doctorFail {
		t.Errorf("unserved group status = %s, want FAIL", got.Status)
	}
}

func rbacClient(allowed bool) *k8sfake.Clientset {
	cs := k8sfake.NewClientset()
	cs.PrependReactor("create", "selfsubjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
			review.Status.Allowed = allowed
			return true, review, nil
		})
	return cs
}

func TestCheckRBAC(t *testing.T) {
	if got := checkRBAC(context.Background(), doctorClients{kube: rbacClient(true)}); got.Status != doctorPass {
		t.Errorf("allowed RBAC status = %s, want PASS", got.Status)
	}
	got := checkRBAC(context.Background(), doctorClients{kube: rbacClient(false)})
	if got.Status != doctorWarn || !strings.Contains(got.Message, "not allowed") {
		t.Errorf("denied RBAC result = %+v, want WARN", got)
	}
	if got := checkRBAC(context.Background(), doctorClients{}); got.Status != doctorWarn {
		t.Errorf("no client status = %s, want WARN", got.Status)
	}
}

func deployment(ready int32, args []string) *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-compliance-operator-controller-manager",
			Namespace: defaultOperatorNamespace,
			Labels:    map[string]string{"control-plane": "controller-manager"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "manager", Args: args}}},
			},
		},
		Status: appsv1.DeploymentStatus{ReadyReplicas: ready},
	}
}

func TestCheckOperatorHealth(t *testing.T) {
	healthy := k8sfake.NewClientset(deployment(1, []string{"--leader-elect"}))
	got := checkOperatorHealth(context.Background(), doctorClients{kube: healthy}, defaultOperatorNamespace)
	if got.Status != doctorPass || !strings.Contains(got.Message, "leader election: enabled") {
		t.Errorf("healthy operator = %+v, want PASS with leader election enabled", got)
	}

	notReady := k8sfake.NewClientset(deployment(0, nil))
	if got := checkOperatorHealth(context.Background(), doctorClients{kube: notReady}, defaultOperatorNamespace); got.Status != doctorFail {
		t.Errorf("unready operator status = %s, want FAIL", got.Status)
	}

	empty := k8sfake.NewClientset()
	got = checkOperatorHealth(context.Background(), doctorClients{kube: empty}, "other-namespace")
	if got.Status != doctorFail || !strings.Contains(got.Remediation, "--operator-namespace") {
		t.Errorf("missing operator = %+v, want FAIL with namespace remediation", got)
	}
}

func TestCheckScanFreshness(t *testing.T) {
	reportWith := func(lastCheck metav1.Time) *securityv1alpha1.TLSComplianceReport {
		return &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: "r1"},
			Status: securityv1alpha1.TLSComplianceReportStatus{
				ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
				LastCheckAt:      &lastCheck,
			},
		}
	}
	newReader := func(lastCheck metav1.Time) client.Reader {
		return fake.NewClientBuilder().WithScheme(scheme).WithObjects(reportWith(lastCheck)).Build()
	}

	fresh := metav1.NewTime(time.Now().Add(-time.Minute))
	if got := checkScanFreshness(context.Background(), doctorClients{reader: newReader(fresh)}, time.Hour); got.Status != doctorPass {
		t.Errorf("fresh reports status = %s, want PASS (%s)", got.Status, got.Message)
	}

	empty := fake.NewClientBuilder().WithScheme(scheme).Build()
	if got := checkScanFreshness(context.Background(), doctorClients{reader: empty}, time.Hour); got.Status != doctorWarn {
		t.Errorf("no reports status = %s, want WARN", got.Status)
	}

	stale := metav1.NewTime(time.Now().Add(-5 * time.Hour))
	if got := checkScanFreshness(context.Background(), doctorClients{reader: newReader(stale)}, time.Hour); got.Status != doctorWarn {
		t.Errorf("stale reports status = %s, want WARN", got.Status)
	}
}

func TestCheckWebhook(t *testing.T) {
	if got := checkWebhook(context.Background(), doctorClients{kube: k8sfake.NewClientset()}, defaultOperatorNamespace); got.Status != doctorWarn {
		t.Errorf("absent webhook status = %s, want WARN", got.Status)
	}

	wh := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "validating-webhook-configuration"},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name: "vtlscompliancetarget.kb.io",
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{Name: "webhook-service", Namespace: defaultOperatorNamespace},
			},
		}},
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "webhook-service", Namespace: defaultOperatorNamespace}}
	endpoints := &corev1.Endpoints{ //nolint:staticcheck // fixture mirrors the served object
		ObjectMeta: metav1.ObjectMeta{Name: "webhook-service", Namespace: defaultOperatorNamespace},
		Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}}, //nolint:staticcheck // fixture mirrors the served object
	}
	healthy := k8sfake.NewClientset(wh, svc, endpoints)
	if got := checkWebhook(context.Background(), doctorClients{kube: healthy}, defaultOperatorNamespace); got.Status != doctorPass {
		t.Errorf("healthy webhook status = %s, want PASS (%s)", got.Status, got.Message)
	}

	noEndpoints := k8sfake.NewClientset(wh, svc)
	if got := checkWebhook(context.Background(), doctorClients{kube: noEndpoints}, defaultOperatorNamespace); got.Status != doctorWarn {
		t.Errorf("webhook without endpoints status = %s, want WARN", got.Status)
	}
}

func TestRunDoctor_JSONAndExitCode(t *testing.T) {
	clients := doctorClients{
		discovery: healthyDiscovery(),
		kube:      k8sfake.NewClientset(deployment(1, nil)),
		reader:    fake.NewClientBuilder().WithScheme(scheme).Build(),
	}

	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, clients, doctorOptions{
		operatorNamespace: defaultOperatorNamespace,
		scanInterval:      time.Hour,
		output:            "json",
		failOnError:       true,
	})
	if err != nil {
		t.Fatalf("healthy cluster returned %v, want nil (only warnings expected)", err)
	}
	var checks []doctorCheck
	if jsonErr := json.Unmarshal(buf.Bytes(), &checks); jsonErr != nil {
		t.Fatalf("JSON output is not parseable: %v\n%s", jsonErr, buf.String())
	}
	for _, c := range checks {
		if c.Status == doctorFail {
			t.Errorf("unexpected FAIL in a healthy cluster: %+v", c)
		}
	}
}

func TestRunDoctor_NoFailOnError(t *testing.T) {
	clients := doctorClients{
		discovery: &failingDiscovery{healthyDiscovery()},
		kube:      k8sfake.NewClientset(),
	}
	var buf bytes.Buffer
	if err := runDoctor(context.Background(), &buf, clients, doctorOptions{
		operatorNamespace: defaultOperatorNamespace,
		scanInterval:      time.Hour,
		output:            "table",
		failOnError:       false,
	}); err != nil {
		t.Fatalf("fail-on-error=false returned %v", err)
	}
	if !strings.Contains(buf.String(), doctorFail) {
		t.Error("table output should contain a FAIL row")
	}
}

func TestRunDoctor_FailsOnError(t *testing.T) {
	clients := doctorClients{discovery: &failingDiscovery{healthyDiscovery()}}
	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, clients, doctorOptions{
		operatorNamespace: defaultOperatorNamespace,
		scanInterval:      time.Hour,
		output:            "table",
		failOnError:       true,
	})
	if err == nil {
		t.Fatal("expected an error when a check FAILs and --fail-on-error is true")
	}
	if !strings.Contains(err.Error(), "check(s) failed") {
		t.Errorf("error = %q, want a failed-check count", err)
	}
}

func TestRunDoctor_RejectsUnknownOutput(t *testing.T) {
	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, doctorClients{}, doctorOptions{
		output: "yaml",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("error = %v, want an unknown-output error", err)
	}
}
