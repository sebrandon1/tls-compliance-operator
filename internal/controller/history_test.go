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
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

func TestComplianceHistory(t *testing.T) {
	scheme := newTestScheme()
	ctx := context.Background()

	t.Run("BasicHistoryAndPruning", func(t *testing.T) {
		crName := "test-history"
		cr := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName,
			},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            "example.com",
				Port:            443,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: "default",
				SourceName:      "myservice",
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).WithStatusSubresource(cr).Build()
		r := &EndpointReconciler{
			Client:            cl,
			Scheme:            scheme,
			MaxHistoryEntries: 3,
		}

		// 1. First scan: Compliant
		result1 := &tlscheck.TLSCheckResult{
			SupportsTLS12: true,
			SupportsTLS13: true,
			CipherSuites: map[string][]string{
				"TLS1.3": {"TLS_AES_128_GCM_SHA256"},
			},
			Certificate: &tlscheck.CertificateDetails{
				Fingerprint: "fingerprint1",
			},
		}

		r.applyCheckResult(ctx, crName, "example.com", 443, result1, nil)

		var updatedCR securityv1alpha1.TLSComplianceReport
		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)

		if len(updatedCR.Status.History) != 1 {
			t.Fatalf("expected 1 history entry, got %d", len(updatedCR.Status.History))
		}
		if updatedCR.Status.History[0].ComplianceStatus != securityv1alpha1.ComplianceStatusCompliant {
			t.Errorf("expected status Compliant, got %s", updatedCR.Status.History[0].ComplianceStatus)
		}
		if updatedCR.Status.History[0].CertFingerprint != "fingerprint1" {
			t.Errorf("expected fingerprint fingerprint1, got %s", updatedCR.Status.History[0].CertFingerprint)
		}

		// 2. Second scan: NonCompliant
		result2 := &tlscheck.TLSCheckResult{
			SupportsTLS10: true,
			CipherSuites: map[string][]string{
				"TLS1.0": {"TLS_RSA_WITH_AES_128_CBC_SHA"},
			},
			Certificate: &tlscheck.CertificateDetails{
				Fingerprint: "fingerprint2",
			},
		}

		r.applyCheckResult(ctx, crName, "example.com", 443, result2, nil)

		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 2 {
			t.Fatalf("expected 2 history entries, got %d", len(updatedCR.Status.History))
		}
		// Index 0 should be latest
		if updatedCR.Status.History[0].ComplianceStatus != securityv1alpha1.ComplianceStatusNonCompliant {
			t.Errorf("expected status NonCompliant at index 0, got %s", updatedCR.Status.History[0].ComplianceStatus)
		}
		if updatedCR.Status.History[1].ComplianceStatus != securityv1alpha1.ComplianceStatusCompliant {
			t.Errorf("expected status Compliant at index 1, got %s", updatedCR.Status.History[1].ComplianceStatus)
		}

		// 3. Third scan: Unreachable
		r.applyCheckResult(ctx, crName, "example.com", 443, nil, errors.New("connection failed"))

		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 3 {
			t.Fatalf("expected 3 history entries, got %d", len(updatedCR.Status.History))
		}
		if updatedCR.Status.History[0].ComplianceStatus != securityv1alpha1.ComplianceStatusUnreachable {
			t.Errorf("expected status Unreachable at index 0, got %s", updatedCR.Status.History[0].ComplianceStatus)
		}

		// 4. Fourth scan: Should prune the oldest entry (Compliant)
		result4 := &tlscheck.TLSCheckResult{
			SupportsTLS13: true,
			Certificate: &tlscheck.CertificateDetails{
				Fingerprint: "fingerprint4",
			},
		}
		r.applyCheckResult(ctx, crName, "example.com", 443, result4, nil)

		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 3 {
			t.Fatalf("expected 3 history entries after pruning, got %d", len(updatedCR.Status.History))
		}
		if updatedCR.Status.History[0].CertFingerprint != "fingerprint4" {
			t.Errorf("expected latest fingerprint fingerprint4, got %s", updatedCR.Status.History[0].CertFingerprint)
		}
		if updatedCR.Status.History[1].ComplianceStatus != securityv1alpha1.ComplianceStatusUnreachable {
			t.Errorf("expected middle entry to be Unreachable, got %s", updatedCR.Status.History[1].ComplianceStatus)
		}
		if updatedCR.Status.History[2].ComplianceStatus != securityv1alpha1.ComplianceStatusNonCompliant {
			t.Errorf("expected oldest entry to be NonCompliant, got %s", updatedCR.Status.History[2].ComplianceStatus)
		}
	})

	t.Run("FailureClearsStaleGradeAndFingerprint", func(t *testing.T) {
		crName := "failure-history"
		cr := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: crName},
			Spec:       securityv1alpha1.TLSComplianceReportSpec{Host: "example.com", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "default", SourceName: "myservice"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).WithStatusSubresource(cr).Build()
		r := &EndpointReconciler{Client: cl, Scheme: scheme, MaxHistoryEntries: 3}

		success := &tlscheck.TLSCheckResult{
			SupportsTLS13: true,
			CipherSuites: map[string][]string{
				"TLS1.3": {"TLS_AES_128_GCM_SHA256"},
			},
			Certificate: &tlscheck.CertificateDetails{Fingerprint: "fingerprint1"},
		}
		r.applyCheckResult(ctx, crName, "example.com", 443, success, nil)
		r.applyCheckResult(ctx, crName, "example.com", 443, nil, errors.New("connection failed"))

		var updatedCR securityv1alpha1.TLSComplianceReport
		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 2 {
			t.Fatalf("expected 2 history entries, got %d", len(updatedCR.Status.History))
		}
		if updatedCR.Status.History[0].ComplianceStatus != securityv1alpha1.ComplianceStatusUnreachable {
			t.Errorf("expected latest status Unreachable, got %s", updatedCR.Status.History[0].ComplianceStatus)
		}
		if updatedCR.Status.History[0].OverallCipherGrade != "" {
			t.Errorf("expected empty grade on failure entry, got %q", updatedCR.Status.History[0].OverallCipherGrade)
		}
		if updatedCR.Status.History[0].CertFingerprint != "" {
			t.Errorf("expected empty fingerprint on failure entry, got %q", updatedCR.Status.History[0].CertFingerprint)
		}
		if updatedCR.Status.CertificateInfo == nil || updatedCR.Status.CertificateInfo.Fingerprint != "fingerprint1" {
			t.Error("expected current status to retain last known certificate info")
		}
	})

	t.Run("Deduplication", func(t *testing.T) {
		crName := "dedup-test"
		cr := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: crName},
			Spec:       securityv1alpha1.TLSComplianceReportSpec{Host: "c", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "d", SourceName: "s"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).WithStatusSubresource(cr).Build()
		r := &EndpointReconciler{Client: cl, Scheme: scheme, MaxHistoryEntries: 10}

		res := &tlscheck.TLSCheckResult{
			SupportsTLS13: true,
			Certificate:   &tlscheck.CertificateDetails{Fingerprint: "f1"},
		}

		// First scan
		r.applyCheckResult(ctx, crName, "c", 443, res, nil)
		// Second scan with same result
		r.applyCheckResult(ctx, crName, "c", 443, res, nil)

		var updatedCR securityv1alpha1.TLSComplianceReport
		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 1 {
			t.Errorf("expected 1 history entry after dedup, got %d", len(updatedCR.Status.History))
		}
	})
}

func TestComplianceHistoryEdgeCases(t *testing.T) {
	scheme := newTestScheme()
	ctx := context.Background()

	t.Run("MaxHistoryEntries=1", func(t *testing.T) {
		crName := "edge-case-1"
		cr := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: crName},
			Spec:       securityv1alpha1.TLSComplianceReportSpec{Host: "a", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "d", SourceName: "s"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).WithStatusSubresource(cr).Build()
		r := &EndpointReconciler{Client: cl, Scheme: scheme, MaxHistoryEntries: 1}

		res1 := &tlscheck.TLSCheckResult{SupportsTLS13: true}
		r.applyCheckResult(ctx, crName, "a", 443, res1, nil)
		res2 := &tlscheck.TLSCheckResult{SupportsTLS10: true}
		r.applyCheckResult(ctx, crName, "a", 443, res2, nil)

		var updatedCR securityv1alpha1.TLSComplianceReport
		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 1 {
			t.Fatalf("expected 1 history entry, got %d", len(updatedCR.Status.History))
		}
		if updatedCR.Status.History[0].ComplianceStatus != securityv1alpha1.ComplianceStatusNonCompliant {
			t.Errorf("expected status NonCompliant, got %s", updatedCR.Status.History[0].ComplianceStatus)
		}
	})

	t.Run("MaxHistoryEntries=0_DefaultsTo10", func(t *testing.T) {
		crName := "edge-case-0"
		cr := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: crName},
			Spec:       securityv1alpha1.TLSComplianceReportSpec{Host: "b", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "d", SourceName: "s"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).WithStatusSubresource(cr).Build()
		r := &EndpointReconciler{Client: cl, Scheme: scheme, MaxHistoryEntries: 0}

		for i := 0; i < 15; i++ {
			// Change status each time to avoid dedup
			res := &tlscheck.TLSCheckResult{SupportsTLS13: true}
			if i%2 == 0 {
				res.SupportsSSL30 = true
			}
			r.applyCheckResult(ctx, crName, "b", 443, res, nil)
		}

		var updatedCR securityv1alpha1.TLSComplianceReport
		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 10 {
			t.Fatalf("expected 10 history entries (default), got %d", len(updatedCR.Status.History))
		}
	})

	t.Run("NilCertificate", func(t *testing.T) {
		crName := "nil-cert-test"
		cr := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{Name: crName},
			Spec:       securityv1alpha1.TLSComplianceReportSpec{Host: "c", Port: 443, SourceKind: securityv1alpha1.SourceKindService, SourceNamespace: "d", SourceName: "s"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).WithStatusSubresource(cr).Build()
		r := &EndpointReconciler{Client: cl, Scheme: scheme, MaxHistoryEntries: 10}

		res := &tlscheck.TLSCheckResult{SupportsTLS13: true}
		r.applyCheckResult(ctx, crName, "c", 443, res, nil)

		var updatedCR securityv1alpha1.TLSComplianceReport
		_ = cl.Get(ctx, types.NamespacedName{Name: crName}, &updatedCR)
		if len(updatedCR.Status.History) != 1 {
			t.Fatalf("expected 1 history entry, got %d", len(updatedCR.Status.History))
		}
		if updatedCR.Status.History[0].CertFingerprint != "" {
			t.Errorf("expected empty cert fingerprint, got %q", updatedCR.Status.History[0].CertFingerprint)
		}
	})
}
