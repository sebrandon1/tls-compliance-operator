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
	"crypto/tls"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

const (
	defaultClientCertKey = "tls.crt"
	defaultClientKeyKey  = "tls.key"
)

// targetForReport returns the TLSComplianceTarget that produced report, or nil
// when the report comes from a discovered resource.
func (r *EndpointReconciler) targetForReport(ctx context.Context, report *securityv1alpha1.TLSComplianceReport) *securityv1alpha1.TLSComplianceTarget {
	if report.Spec.SourceKind != securityv1alpha1.SourceKindTarget || report.Spec.SourceName == "" {
		return nil
	}
	var target securityv1alpha1.TLSComplianceTarget
	if err := r.Get(ctx, client.ObjectKey{Name: report.Spec.SourceName}, &target); err != nil {
		return nil
	}
	return &target
}

// targetCheckOptions builds the per-target check overrides for the report
// named crName. It returns nil when the report is not target-sourced or the
// target configures no overrides.
func (r *EndpointReconciler) targetCheckOptions(ctx context.Context, crName string) (*tlscheck.CheckOptions, error) {
	var report securityv1alpha1.TLSComplianceReport
	err := r.Get(ctx, client.ObjectKey{Name: crName}, &report)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	target := r.targetForReport(ctx, &report)
	if target == nil || target.Spec.Scan == nil {
		return nil, nil
	}
	scan := target.Spec.Scan

	opts := &tlscheck.CheckOptions{TLSVersions: scan.TLSVersions, EnumerateCiphers: scan.EnumerateCiphers}
	if scan.Timeout != nil {
		opts.Timeout = scan.Timeout.Duration
	}
	if scan.ClientCertificate != nil {
		cert, err := r.loadClientCertificate(ctx, scan.ClientCertificate)
		if err != nil {
			return nil, fmt.Errorf("target %s client certificate: %w", target.Name, err)
		}
		opts.ClientCert = cert
	}
	return opts, nil
}

// loadClientCertificate reads a PEM client certificate and key from a Secret.
func (r *EndpointReconciler) loadClientCertificate(ctx context.Context, ref *securityv1alpha1.TargetClientCertificateRef) (*tls.Certificate, error) {
	certKey := ref.CertKey
	if certKey == "" {
		certKey = defaultClientCertKey
	}
	keyKey := ref.KeyKey
	if keyKey == "" {
		keyKey = defaultClientKeyKey
	}

	var secret corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &secret); err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	certPEM, ok := secret.Data[certKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no %q key", ref.Namespace, ref.Name, certKey)
	}
	keyPEM, ok := secret.Data[keyKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no %q key", ref.Namespace, ref.Name, keyKey)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse key pair from secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	return &cert, nil
}

// targetScanInterval returns the per-target scan interval override, or 0 when
// the report is not target-sourced or sets none.
func (r *EndpointReconciler) targetScanInterval(ctx context.Context, report *securityv1alpha1.TLSComplianceReport) time.Duration {
	target := r.targetForReport(ctx, report)
	if target == nil || target.Spec.Scan == nil || target.Spec.Scan.Interval == nil {
		return 0
	}
	return target.Spec.Scan.Interval.Duration
}

// targetProfile returns the built-in TLS profile name selected by the target
// that produced report, or "" when none is selected.
func (r *EndpointReconciler) targetProfile(ctx context.Context, report *securityv1alpha1.TLSComplianceReport) string {
	target := r.targetForReport(ctx, report)
	if target == nil || target.Spec.Scan == nil {
		return ""
	}
	return target.Spec.Scan.Profile
}

// checkTimeoutFor returns the wall-clock budget for one async check, widened so
// a per-target probe timeout and the retry backoff both fit inside it.
func (r *EndpointReconciler) checkTimeoutFor(crName string) time.Duration {
	timeout := r.asyncCheckTimeout()
	if r.checkTimeout > 0 {
		return timeout
	}
	opts, err := r.targetCheckOptions(r.managerCtx(), crName)
	if err != nil || opts == nil || opts.Timeout <= 0 {
		return timeout
	}
	attempts := int64(1 + r.MaxRetries)
	if attempts < 1 {
		attempts = 1
	}
	backoffCap := r.MaxBackoff
	if backoffCap <= 0 {
		backoffCap = 5 * time.Minute
	}
	budget := time.Duration(attempts)*opts.Timeout + time.Duration(attempts-1)*backoffCap
	if budget > timeout {
		return budget
	}
	return timeout
}
