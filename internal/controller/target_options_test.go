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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

// testKeyPairPEM returns a self-signed PEM certificate and its EC private key.
func testKeyPairPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// targetReport returns a report sourced from the named TLSComplianceTarget.
func targetReport() *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "rpt"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:       "example.com",
			Port:       443,
			SourceKind: securityv1alpha1.SourceKindTarget,
			SourceName: "tgt",
		},
	}
}

func newScanTarget(scan *securityv1alpha1.TargetScanConfig) *securityv1alpha1.TLSComplianceTarget {
	port := int32(443)
	return &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "tgt"},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: "example.com",
			Port: &port,
			Scan: scan,
		},
	}
}

func TestTargetCheckOptions_NonTargetReport(t *testing.T) {
	scheme := newTestScheme()
	report := &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "rpt"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host: "example.com", Port: 443,
			SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "svc",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()
	r := &EndpointReconciler{Client: c, Scheme: scheme}

	opts, err := r.targetCheckOptions(context.Background(), "rpt")
	if err != nil {
		t.Fatalf("targetCheckOptions() error = %v", err)
	}
	if opts != nil {
		t.Errorf("targetCheckOptions() = %+v, want nil for a non-target report", opts)
	}
}

func TestTargetCheckOptions_Overrides(t *testing.T) {
	timeout := metav1.Duration{Duration: 9 * time.Second}
	enumerate := false
	target := newScanTarget(&securityv1alpha1.TargetScanConfig{
		Timeout:          &timeout,
		TLSVersions:      []string{"1.2", "1.3"},
		EnumerateCiphers: &enumerate,
	})
	scheme := newTestScheme()
	r := &EndpointReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(target, targetReport()).Build(), Scheme: scheme}

	opts, err := r.targetCheckOptions(context.Background(), "rpt")
	if err != nil {
		t.Fatalf("targetCheckOptions() error = %v", err)
	}
	if opts == nil {
		t.Fatal("targetCheckOptions() = nil, want overrides")
	}
	if opts.Timeout != 9*time.Second {
		t.Errorf("Timeout = %v, want 9s", opts.Timeout)
	}
	if opts.EnumerateCiphers == nil || *opts.EnumerateCiphers {
		t.Errorf("EnumerateCiphers = %v, want false", opts.EnumerateCiphers)
	}
	if len(opts.TLSVersions) != 2 {
		t.Errorf("TLSVersions = %v, want two entries", opts.TLSVersions)
	}
}

func TestTargetCheckOptions_ClientCertificate(t *testing.T) {
	certPEM, keyPEM := testKeyPairPEM(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "certs", Name: "client"},
		Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM},
	}
	ref := &securityv1alpha1.TargetClientCertificateRef{Namespace: "certs", Name: "client"}
	target := newScanTarget(&securityv1alpha1.TargetScanConfig{ClientCertificate: ref})

	scheme := newTestScheme()
	r := &EndpointReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(target, targetReport(), secret).Build(), Scheme: scheme}

	opts, err := r.targetCheckOptions(context.Background(), "rpt")
	if err != nil {
		t.Fatalf("targetCheckOptions() error = %v", err)
	}
	if opts == nil || opts.ClientCert == nil {
		t.Fatalf("targetCheckOptions() = %+v, want a client certificate", opts)
	}
	if len(opts.ClientCert.Certificate) == 0 {
		t.Error("expected the client certificate chain to be parsed")
	}
}

func TestLoadClientCertificate_MissingKey(t *testing.T) {
	certPEM, _ := testKeyPairPEM(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "certs", Name: "client"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}
	target := newScanTarget(&securityv1alpha1.TargetScanConfig{
		ClientCertificate: &securityv1alpha1.TargetClientCertificateRef{Namespace: "certs", Name: "client"},
	})

	scheme := newTestScheme()
	r := &EndpointReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(target, targetReport(), secret).Build(), Scheme: scheme}

	if _, err := r.targetCheckOptions(context.Background(), "rpt"); err == nil {
		t.Fatal("targetCheckOptions() error = nil, want an error for a missing key")
	}
}

func TestTargetScanIntervalAndProfile(t *testing.T) {
	interval := metav1.Duration{Duration: 15 * time.Minute}
	target := newScanTarget(&securityv1alpha1.TargetScanConfig{
		Interval: &interval,
		Profile:  "Modern",
	})

	scheme := newTestScheme()
	r := &EndpointReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(target, targetReport()).Build(), Scheme: scheme}
	report := targetReport()

	if got := r.targetScanInterval(context.Background(), report); got != 15*time.Minute {
		t.Errorf("targetScanInterval() = %v, want 15m", got)
	}
	if got := r.targetProfile(context.Background(), report); got != "Modern" {
		t.Errorf("targetProfile() = %q, want Modern", got)
	}
}

func TestNextScanAt_UsesTargetInterval(t *testing.T) {
	interval := metav1.Duration{Duration: 2 * time.Minute}
	target := newScanTarget(&securityv1alpha1.TargetScanConfig{Interval: &interval})

	scheme := newTestScheme()
	r := &EndpointReconciler{
		Client:       fake.NewClientBuilder().WithScheme(scheme).WithObjects(target).Build(),
		Scheme:       scheme,
		ScanInterval: time.Hour,
	}
	report := targetReport()

	lastSeen := metav1.Now()
	next := r.nextScanAt(context.Background(), report, &lastSeen)
	if next == nil {
		t.Fatal("nextScanAt() = nil, want a time")
	}
	got := next.Sub(lastSeen.Time)
	if got < 90*time.Second || got > 150*time.Second {
		t.Errorf("nextScanAt() interval = %v, want about 2m", got)
	}
}

func TestCheckTimeoutFor_WidensForTargetTimeout(t *testing.T) {
	timeout := metav1.Duration{Duration: 30 * time.Second}
	target := newScanTarget(&securityv1alpha1.TargetScanConfig{Timeout: &timeout})

	scheme := newTestScheme()
	r := &EndpointReconciler{
		Client:     fake.NewClientBuilder().WithScheme(scheme).WithObjects(target, targetReport()).Build(),
		Scheme:     scheme,
		ManagerCtx: context.Background(),
	}

	if got := r.checkTimeoutFor("rpt"); got < 30*time.Second {
		t.Errorf("checkTimeoutFor() = %v, want at least the 30s target timeout", got)
	}
}

func TestCheckProfileCompliance_SelectedProfile(t *testing.T) {
	target := newScanTarget(&securityv1alpha1.TargetScanConfig{Profile: "Modern"})
	scheme := newTestScheme()
	r := &EndpointReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(target, targetReport()).Build(), Scheme: scheme}

	cr := targetReport()
	result := &tlscheck.TLSCheckResult{SupportsTLS12: true}
	r.checkProfileCompliance(context.Background(), cr, result)

	if cr.Status.SelectedProfileCompliance == nil {
		t.Fatal("SelectedProfileCompliance = nil, want a result for the Modern profile")
	}
	if cr.Status.SelectedProfileCompliance.ProfileType != "Modern" {
		t.Errorf("ProfileType = %q, want Modern", cr.Status.SelectedProfileCompliance.ProfileType)
	}
	if cr.Status.SelectedProfileCompliance.Compliant {
		t.Error("expected a TLS 1.2-only endpoint to be non-compliant with Modern")
	}
	if cr.Status.SelectedProfileCompliance.MinTLSVersionMet {
		t.Error("expected MinTLSVersionMet to be false for Modern against TLS 1.2 only")
	}
}

func TestCheckProfileCompliance_NoSelectedProfile(t *testing.T) {
	scheme := newTestScheme()
	r := &EndpointReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).Build(), Scheme: scheme}

	cr := targetReport()
	result := &tlscheck.TLSCheckResult{SupportsTLS13: true}
	r.checkProfileCompliance(context.Background(), cr, result)

	if cr.Status.SelectedProfileCompliance != nil {
		t.Errorf("SelectedProfileCompliance = %+v, want nil", cr.Status.SelectedProfileCompliance)
	}
}
