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

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidateTargetSpec_SSRF(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// Allowed external hosts
		{"external IPv4", "8.8.8.8", false},
		{"external IPv6", "2001:4860:4860::8888", false},
		{"external hostname", "example.com", false},
		{"external subdomain", "api.example.com", false},

		// Blocked: IPv4 loopback
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.0.0.2", "127.0.0.2", true},

		// Blocked: IPv6 loopback
		{"ipv6 loopback", "::1", true},

		// Blocked: link-local / cloud metadata
		{"link-local", "169.254.1.1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"ipv6 link-local", "fe80::1", true},

		// Blocked: RFC 1918 private
		{"10.x", "10.0.0.1", true},
		{"172.16.x", "172.16.0.1", true},
		{"172.31.x", "172.31.255.255", true},
		{"192.168.x", "192.168.1.1", true},

		// Blocked: IPv6 ULA
		{"ipv6 ULA", "fd00::1", true},

		// Blocked: unspecified
		{"unspecified", "0.0.0.0", true},

		// Allowed: 172.32.x is NOT RFC 1918
		{"172.32.x allowed", "172.32.0.1", false},

		// Blocked: internal hostnames
		{"localhost", "localhost", true},
		{"subdomain.localhost", "app.localhost", true},
		{"svc.cluster.local", "myapp.default.svc.cluster.local", true},
		{"metadata.google.internal", "metadata.google.internal", true},

		// Allowed: similar but not internal hostnames
		{"notlocalhost", "notlocalhost.com", false},
		{"cluster.local.example.com", "cluster.local.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &TLSComplianceTarget{}
			target.Spec.Host = tt.host
			target.Spec.Port = 443
			errs := validateTargetSpec(target)
			if tt.wantErr && len(errs) == 0 {
				t.Errorf("expected validation error for host %q, got none", tt.host)
			}
			if !tt.wantErr && len(errs) > 0 {
				t.Errorf("unexpected validation error for host %q: %v", tt.host, errs)
			}
		})
	}
}

func TestValidateTargetSpec_Wildcard(t *testing.T) {
	target := &TLSComplianceTarget{}
	target.Spec.Host = "*.example.com"
	target.Spec.Port = 443
	errs := validateTargetSpec(target)
	if len(errs) == 0 {
		t.Error("expected validation error for wildcard host")
	}
}

func TestValidateTargetSpec_InvalidDNS(t *testing.T) {
	target := &TLSComplianceTarget{}
	target.Spec.Host = "not a valid host!"
	target.Spec.Port = 443
	errs := validateTargetSpec(target)
	if len(errs) == 0 {
		t.Error("expected validation error for invalid DNS name")
	}
}

func setTargetClient(t *testing.T, scheme *runtime.Scheme, objects ...runtime.Object) {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, obj := range objects {
		builder = builder.WithRuntimeObjects(obj)
	}
	cl := builder.Build()

	targetClientMu.Lock()
	targetClient = cl
	targetClientMu.Unlock()

	t.Cleanup(func() {
		targetClientMu.Lock()
		targetClient = nil
		targetClientMu.Unlock()
	})
}

func newWebhookTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	return scheme
}

func TestValidateNoDuplicate_BlocksDuplicateHostPort(t *testing.T) {
	scheme := newWebhookTestScheme()
	existing := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-target"},
		Spec:       TLSComplianceTargetSpec{Host: "example.com", Port: 443},
	}
	setTargetClient(t, scheme, existing)

	newTarget := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "new-target"},
		Spec:       TLSComplianceTargetSpec{Host: "example.com", Port: 443},
	}

	err := validateNoDuplicate(context.Background(), newTarget, "")
	if err == nil {
		t.Fatal("expected error for duplicate host:port")
	}
	if !strings.Contains(err.Error(), "duplicate host:port") {
		t.Errorf("error = %q, want it to contain 'duplicate host:port'", err.Error())
	}
}

func TestValidateNoDuplicate_AllowsSameHostDifferentPort(t *testing.T) {
	scheme := newWebhookTestScheme()
	existing := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-target"},
		Spec:       TLSComplianceTargetSpec{Host: "example.com", Port: 443},
	}
	setTargetClient(t, scheme, existing)

	newTarget := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "new-target"},
		Spec:       TLSComplianceTargetSpec{Host: "example.com", Port: 8443},
	}

	err := validateNoDuplicate(context.Background(), newTarget, "")
	if err != nil {
		t.Errorf("unexpected error for same host different port: %v", err)
	}
}

func TestValidateNoDuplicate_AllowsSelfOnUpdate(t *testing.T) {
	scheme := newWebhookTestScheme()
	existing := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "my-target"},
		Spec:       TLSComplianceTargetSpec{Host: "example.com", Port: 443},
	}
	setTargetClient(t, scheme, existing)

	sameTarget := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "my-target"},
		Spec:       TLSComplianceTargetSpec{Host: "example.com", Port: 443},
	}

	err := validateNoDuplicate(context.Background(), sameTarget, "my-target")
	if err != nil {
		t.Errorf("unexpected error for self on update: %v", err)
	}
}

func TestValidateNoDuplicate_NilClientAllows(t *testing.T) {
	targetClientMu.Lock()
	targetClient = nil
	targetClientMu.Unlock()

	target := &TLSComplianceTarget{
		Spec: TLSComplianceTargetSpec{Host: "example.com", Port: 443},
	}

	err := validateNoDuplicate(context.Background(), target, "")
	if err != nil {
		t.Errorf("unexpected error when targetClient is nil: %v", err)
	}
}

func TestValidateCreate_ValidTarget(t *testing.T) {
	scheme := newWebhookTestScheme()
	setTargetClient(t, scheme)

	target := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "valid-target"},
		Spec:       TLSComplianceTargetSpec{Host: "new.example.com", Port: 443},
	}

	validator := &TLSComplianceTargetValidator{}
	_, err := validator.ValidateCreate(context.Background(), target)
	if err != nil {
		t.Errorf("unexpected error for valid target: %v", err)
	}
}

func TestValidateCreate_DuplicateTarget(t *testing.T) {
	scheme := newWebhookTestScheme()
	existing := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-target"},
		Spec:       TLSComplianceTargetSpec{Host: "dup.example.com", Port: 443},
	}
	setTargetClient(t, scheme, existing)

	target := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "new-target"},
		Spec:       TLSComplianceTargetSpec{Host: "dup.example.com", Port: 443},
	}

	validator := &TLSComplianceTargetValidator{}
	_, err := validator.ValidateCreate(context.Background(), target)
	if err == nil {
		t.Fatal("expected error for duplicate target on create")
	}
	if !strings.Contains(err.Error(), "duplicate host:port") {
		t.Errorf("error = %q, want it to contain 'duplicate host:port'", err.Error())
	}
}

func TestValidateUpdate_BlocksDuplicateOnHostChange(t *testing.T) {
	scheme := newWebhookTestScheme()
	existing := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "target-a"},
		Spec:       TLSComplianceTargetSpec{Host: "a.example.com", Port: 443},
	}
	setTargetClient(t, scheme, existing)

	oldTarget := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "target-b"},
		Spec:       TLSComplianceTargetSpec{Host: "b.example.com", Port: 443},
	}
	newTarget := &TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "target-b"},
		Spec:       TLSComplianceTargetSpec{Host: "a.example.com", Port: 443},
	}

	validator := &TLSComplianceTargetValidator{}
	_, err := validator.ValidateUpdate(context.Background(), oldTarget, newTarget)
	if err == nil {
		t.Fatal("expected error when updating to duplicate host:port")
	}
	if !strings.Contains(err.Error(), "duplicate host:port") {
		t.Errorf("error = %q, want it to contain 'duplicate host:port'", err.Error())
	}
}
