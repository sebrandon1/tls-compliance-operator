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
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlsprofile"
)

// routeGVK is the GroupVersionKind for OpenShift Routes, defined once to avoid repetition.
var routeGVK = schema.GroupVersionKind{
	Group:   "route.openshift.io",
	Version: "v1",
	Kind:    "Route",
}

// Event reasons for Kubernetes events
const (
	EventReasonTLSNonCompliant     = "TLSNonCompliant"
	EventReasonComplianceChanged   = "ComplianceChanged"
	EventReasonCertificateExpiring = "CertificateExpiring"
	EventReasonCertificateExpired  = "CertificateExpired"
	EventReasonEndpointDiscovered  = "EndpointDiscovered"
	EventReasonRetryExhausted      = "RetryExhausted"
)

// EndpointReconciler reconciles Service, Ingress, and Route resources
type EndpointReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	TLSChecker        tlscheck.Checker
	Recorder          record.EventRecorder
	IncludeNamespaces map[string]bool
	ExcludeNamespaces map[string]bool
	CertExpiryDays    int
	RouteAPIAvailable bool
	ProfileFetcher    *tlsprofile.Fetcher
	Workers           int
	MaxRetries        int
	RetryBackoff      time.Duration
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=ingresscontrollers,verbs=get;list;watch
// +kubebuilder:rbac:groups=machineconfiguration.openshift.io,resources=kubeletconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancereports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancereports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancereports/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancetargets,verbs=get;list;watch

// Reconcile handles Service events and creates/updates TLSComplianceReport CRs
func (r *EndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Check if namespace is excluded
	if r.isNamespaceFiltered(req.Namespace) {
		return ctrl.Result{}, nil
	}

	// Try to fetch as Service first (primary watch)
	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			metrics.RecordReconcile("success")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to fetch Service")
		metrics.RecordReconcile("error")
		return ctrl.Result{}, err
	}

	// Extract endpoints from Service
	endpoints := endpoint.ExtractFromService(&svc)
	if len(endpoints) == 0 {
		metrics.RecordReconcile("success")
		return ctrl.Result{}, nil
	}

	// Process each endpoint
	for _, ep := range endpoints {
		if err := r.processEndpoint(ctx, ep); err != nil {
			logger.Error(err, "failed to process endpoint", "host", ep.Host, "port", ep.Port)
		}
	}

	metrics.RecordReconcile("success")
	return ctrl.Result{}, nil
}

// ReconcileIngress handles Ingress events
func (r *EndpointReconciler) ReconcileIngress(ctx context.Context, req ctrl.Request) {
	logger := log.FromContext(ctx)

	if r.isNamespaceFiltered(req.Namespace) {
		return
	}

	var ing networkingv1.Ingress
	if err := r.Get(ctx, req.NamespacedName, &ing); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "unable to fetch Ingress")
		}
		return
	}

	endpoints := endpoint.ExtractFromIngress(&ing)
	for _, ep := range endpoints {
		if err := r.processEndpoint(ctx, ep); err != nil {
			logger.Error(err, "failed to process Ingress endpoint", "host", ep.Host)
		}
	}
}

// ReconcileRoute handles Route events
func (r *EndpointReconciler) ReconcileRoute(ctx context.Context, req ctrl.Request) {
	logger := log.FromContext(ctx)

	if r.isNamespaceFiltered(req.Namespace) {
		return
	}

	// Fetch Route as unstructured
	route := &unstructured.Unstructured{}
	route.SetGroupVersionKind(routeGVK)

	if err := r.Get(ctx, req.NamespacedName, route); err != nil {
		if !apierrors.IsNotFound(err) && ctx.Err() == nil {
			logger.Error(err, "unable to fetch Route")
		}
		return
	}

	endpoints := endpoint.ExtractFromRoute(route)
	for _, ep := range endpoints {
		if err := r.processEndpoint(ctx, ep); err != nil {
			logger.Error(err, "failed to process Route endpoint", "host", ep.Host)
		}
	}
}

// ReconcileTarget handles TLSComplianceTarget events
func (r *EndpointReconciler) ReconcileTarget(ctx context.Context, req ctrl.Request) {
	logger := log.FromContext(ctx)

	var target securityv1alpha1.TLSComplianceTarget
	if err := r.Get(ctx, req.NamespacedName, &target); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "unable to fetch TLSComplianceTarget")
		}
		return
	}

	ep := endpoint.Endpoint{
		Host:            target.Spec.Host,
		Port:            target.Spec.Port,
		SourceKind:      string(securityv1alpha1.SourceKindTarget),
		SourceNamespace: "cluster-scoped",
		SourceName:      target.Name,
	}

	if err := r.processEndpoint(ctx, ep); err != nil {
		logger.Error(err, "failed to process Target endpoint", "host", ep.Host, "port", ep.Port)
	}
}

// processEndpoint creates or updates a TLSComplianceReport CR for an endpoint
func (r *EndpointReconciler) processEndpoint(ctx context.Context, ep endpoint.Endpoint) error {
	logger := log.FromContext(ctx)
	crName := endpoint.GenerateCRName(ep)
	now := metav1.Now()

	// Try to get existing CR
	var existingCR securityv1alpha1.TLSComplianceReport
	err := r.Get(ctx, client.ObjectKey{Name: crName}, &existingCR)

	if apierrors.IsNotFound(err) {
		// Create new CR
		cr := &securityv1alpha1.TLSComplianceReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName,
			},
			Spec: securityv1alpha1.TLSComplianceReportSpec{
				Host:            ep.Host,
				Port:            ep.Port,
				SourceKind:      securityv1alpha1.SourceKind(ep.SourceKind),
				SourceNamespace: ep.SourceNamespace,
				SourceName:      ep.SourceName,
			},
		}

		if err := r.Create(ctx, cr); err != nil {
			return fmt.Errorf("failed to create TLSComplianceReport: %w", err)
		}

		// Update status
		cr.Status = securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			LastSeenAt:       &now,
			Conditions: []metav1.Condition{
				{
					Type:               "Available",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: now,
					Reason:             "EndpointDiscovered",
					Message:            fmt.Sprintf("Endpoint %s:%d discovered from %s/%s", ep.Host, ep.Port, ep.SourceNamespace, ep.SourceName),
				},
			},
		}

		if err := r.Status().Update(ctx, cr); err != nil {
			return fmt.Errorf("failed to update TLSComplianceReport status: %w", err)
		}

		logger.Info("created TLSComplianceReport", "name", crName, "host", ep.Host, "port", ep.Port)

		if r.Recorder != nil {
			r.Recorder.Event(cr, corev1.EventTypeNormal, EventReasonEndpointDiscovered,
				fmt.Sprintf("Discovered TLS endpoint %s:%d from %s %s/%s", ep.Host, ep.Port, ep.SourceKind, ep.SourceNamespace, ep.SourceName))
		}

		// Launch async TLS check using the caller's context for cancellation
		go r.performTLSCheck(ctx, crName, ep.Host, int(ep.Port))

		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get TLSComplianceReport: %w", err)
	}

	// Update LastSeenAt on existing CR
	existingCR.Status.LastSeenAt = &now
	if err := r.Status().Update(ctx, &existingCR); err != nil {
		return fmt.Errorf("failed to update TLSComplianceReport LastSeenAt: %w", err)
	}

	return nil
}

// performTLSCheck runs the TLS check and updates the CR status.
// On transient failures, it retries with exponential backoff up to MaxRetries times.
func (r *EndpointReconciler) performTLSCheck(ctx context.Context, crName, host string, port int) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.TLSChecker == nil {
		return
	}

	maxAttempts := 1 + r.MaxRetries
	backoff := r.RetryBackoff
	if backoff <= 0 {
		backoff = 30 * time.Second
	}

	var result *tlscheck.TLSCheckResult
	var checkErr error

	for attempt := range maxAttempts {
		result, checkErr = r.TLSChecker.CheckEndpoint(ctx, host, port)

		// Success — break out
		if checkErr == nil {
			break
		}

		// Non-transient failure — no retry
		if !result.FailureReason.IsTransient() {
			break
		}

		// Transient failure with retries remaining
		if attempt < maxAttempts-1 {
			retryDelay := backoff * time.Duration(1<<uint(attempt))
			logger.Info("transient TLS check failure, retrying",
				"attempt", attempt+1,
				"maxAttempts", maxAttempts,
				"reason", string(result.FailureReason),
				"retryDelay", retryDelay)

			metrics.RecordRetry(string(result.FailureReason))

			// Update CR with retry status
			r.updateRetryStatus(ctx, crName, attempt+1, retryDelay, result.FailureReason, checkErr)

			// Context-aware sleep
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
			}
		}
	}

	// Re-fetch the CR to avoid conflicts
	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get TLSComplianceReport for TLS check update")
		return
	}

	now := metav1.Now()
	cr.Status.LastCheckAt = &now
	cr.Status.CheckCount++
	cr.Status.RetryCount = 0
	cr.Status.NextRetryAt = nil

	portStr := fmt.Sprintf("%d", port)

	if checkErr != nil {
		cr.Status.ComplianceStatus = failureReasonToComplianceStatus(result.FailureReason)
		cr.Status.ConsecutiveErrors++
		cr.Status.LastError = checkErr.Error()

		if err := r.Status().Update(ctx, &cr); err != nil {
			logger.Error(err, "failed to update TLSComplianceReport after check error")
		}

		// Emit retry exhausted event if retries were attempted on a transient failure
		if result.FailureReason.IsTransient() && r.MaxRetries > 0 {
			metrics.RecordRetriesExhausted()
			if r.Recorder != nil {
				r.Recorder.Event(&cr, corev1.EventTypeWarning, EventReasonRetryExhausted,
					fmt.Sprintf("TLS check retries exhausted for %s:%d after %d attempts: %s",
						host, port, maxAttempts, result.FailureReason))
			}
		}
		return
	}

	// Reset error state on success
	cr.Status.ConsecutiveErrors = 0
	cr.Status.LastError = ""

	// Store old status for change detection
	oldComplianceStatus := cr.Status.ComplianceStatus

	// Update TLS version support
	cr.Status.TLSVersions = securityv1alpha1.TLSVersionSupport{
		TLS10: result.SupportsTLS10,
		TLS11: result.SupportsTLS11,
		TLS12: result.SupportsTLS12,
		TLS13: result.SupportsTLS13,
	}

	// Update cipher suites and grades (compute once, reuse for overall)
	cr.Status.CipherSuites = result.CipherSuites
	cipherGrades := tlscheck.GradeCipherSuites(result.CipherSuites)
	cr.Status.CipherStrengthGrades = cipherGrades
	cr.Status.OverallCipherGrade = tlscheck.OverallGrade(result.CipherSuites, cipherGrades)

	// Update negotiated curves and quantum readiness
	cr.Status.NegotiatedCurves = result.NegotiatedCurves
	cr.Status.QuantumReady = isQuantumReady(result.NegotiatedCurves)

	// Update certificate info
	if result.Certificate != nil {
		notBefore := metav1.NewTime(result.Certificate.NotBefore)
		notAfter := metav1.NewTime(result.Certificate.NotAfter)
		cr.Status.CertificateInfo = &securityv1alpha1.CertificateInfo{
			Issuer:          result.Certificate.Issuer,
			Subject:         result.Certificate.Subject,
			NotBefore:       &notBefore,
			NotAfter:        &notAfter,
			DNSNames:        result.Certificate.DNSNames,
			IsExpired:       result.Certificate.IsExpired,
			DaysUntilExpiry: result.Certificate.DaysUntilExpiry,
		}

		// Record cert expiry metric
		metrics.RecordCertExpiry(host, portStr, float64(result.Certificate.DaysUntilExpiry))
	}

	// Check OpenShift TLS security profile compliance
	r.checkProfileCompliance(&cr, result)

	// Determine compliance status
	complianceStatus := determineComplianceStatus(result)
	cr.Status.ComplianceStatus = complianceStatus

	// Record metrics
	metrics.RecordCheckDuration(result.CheckDuration.Seconds())
	metrics.RecordVersionSupport(host, portStr, "1.0", result.SupportsTLS10)
	metrics.RecordVersionSupport(host, portStr, "1.1", result.SupportsTLS11)
	metrics.RecordVersionSupport(host, portStr, "1.2", result.SupportsTLS12)
	metrics.RecordVersionSupport(host, portStr, "1.3", result.SupportsTLS13)

	// Update conditions
	r.updateConditions(&cr, complianceStatus, result)

	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "failed to update TLSComplianceReport with check results")
		return
	}

	// Emit events
	r.emitComplianceEvents(&cr, oldComplianceStatus, result)
}

// updateRetryStatus updates the CR with intermediate retry status information
func (r *EndpointReconciler) updateRetryStatus(ctx context.Context, crName string, retryCount int, retryDelay time.Duration, reason tlscheck.FailureReason, checkErr error) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get TLSComplianceReport for retry status update")
		return
	}

	nextRetry := metav1.NewTime(time.Now().Add(retryDelay))
	cr.Status.RetryCount = retryCount
	cr.Status.NextRetryAt = &nextRetry
	cr.Status.LastError = checkErr.Error()
	cr.Status.ConsecutiveErrors++

	cr.Status.ComplianceStatus = failureReasonToComplianceStatus(reason)

	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "failed to update TLSComplianceReport retry status")
	}
}

// determineComplianceStatus determines the compliance status from TLS check results.
// Compliance is based on whether the endpoint supports modern TLS (1.2+).
// Supporting older versions (1.0/1.1) alongside modern ones is acceptable
// since OpenShift TLS security profiles may require them (e.g. the "Old" profile).
func determineComplianceStatus(result *tlscheck.TLSCheckResult) securityv1alpha1.ComplianceStatus {
	if result.SupportsTLS12 || result.SupportsTLS13 {
		return securityv1alpha1.ComplianceStatusCompliant
	}
	if result.SupportsTLS10 || result.SupportsTLS11 {
		// Only legacy TLS versions, no modern TLS support
		return securityv1alpha1.ComplianceStatusNonCompliant
	}
	return securityv1alpha1.ComplianceStatusUnknown
}

// isQuantumReady returns true if any negotiated curve uses a post-quantum
// key exchange algorithm (identified by containing "MLKEM" in the name).
func isQuantumReady(curves map[string]string) bool {
	for _, curve := range curves {
		if strings.Contains(curve, "MLKEM") {
			return true
		}
	}
	return false
}

// checkProfileCompliance evaluates the endpoint against OpenShift TLS security
// profiles if a ProfileFetcher is configured. Populates the per-component
// compliance fields on the CR status.
func (r *EndpointReconciler) checkProfileCompliance(cr *securityv1alpha1.TLSComplianceReport, result *tlscheck.TLSCheckResult) {
	if r.ProfileFetcher == nil {
		return
	}

	profiles := r.ProfileFetcher.GetAllProfiles()

	for component, profile := range profiles {
		compResult := tlsprofile.CheckCompliance(
			profile,
			result.SupportsTLS10,
			result.SupportsTLS11,
			result.SupportsTLS12,
			result.SupportsTLS13,
			result.CipherSuites,
		)

		crdResult := &securityv1alpha1.TLSProfileComplianceResult{
			ProfileType:       compResult.ProfileType,
			Compliant:         compResult.Compliant,
			MinTLSVersionMet:  compResult.MinTLSVersionMet,
			DisallowedCiphers: compResult.DisallowedCiphers,
		}

		switch component {
		case tlsprofile.ComponentIngressController:
			cr.Status.IngressProfileCompliance = crdResult
		case tlsprofile.ComponentAPIServer:
			cr.Status.APIServerProfileCompliance = crdResult
		case tlsprofile.ComponentKubeletConfig:
			cr.Status.KubeletProfileCompliance = crdResult
		}
	}
}

// updateConditions sets Kubernetes conditions based on check results
func (r *EndpointReconciler) updateConditions(cr *securityv1alpha1.TLSComplianceReport, complianceStatus securityv1alpha1.ComplianceStatus, result *tlscheck.TLSCheckResult) {
	now := metav1.Now()

	// TLS Compliant condition
	complianceCondition := metav1.Condition{
		Type:               "TLSCompliant",
		LastTransitionTime: now,
	}

	switch complianceStatus {
	case securityv1alpha1.ComplianceStatusCompliant:
		complianceCondition.Status = metav1.ConditionTrue
		complianceCondition.Reason = "Compliant"
		complianceCondition.Message = "Endpoint supports modern TLS (1.2 or 1.3)"
	case securityv1alpha1.ComplianceStatusNonCompliant:
		complianceCondition.Status = metav1.ConditionFalse
		complianceCondition.Reason = "NonCompliant"
		complianceCondition.Message = "Endpoint only supports legacy TLS versions (no TLS 1.2 or 1.3)"
	default:
		complianceCondition.Status = metav1.ConditionUnknown
		complianceCondition.Reason = "Unknown"
		complianceCondition.Message = "TLS compliance status could not be determined"
	}

	setCondition(&cr.Status.Conditions, complianceCondition)

	// Certificate Valid condition
	if result.Certificate != nil {
		certCondition := metav1.Condition{
			Type:               "CertificateValid",
			LastTransitionTime: now,
		}

		if result.Certificate.IsExpired {
			certCondition.Status = metav1.ConditionFalse
			certCondition.Reason = "Expired"
			certCondition.Message = "TLS certificate has expired"
		} else if result.Certificate.DaysUntilExpiry <= r.CertExpiryDays {
			certCondition.Status = metav1.ConditionFalse
			certCondition.Reason = "Expiring"
			certCondition.Message = fmt.Sprintf("TLS certificate expires in %d days", result.Certificate.DaysUntilExpiry)
		} else {
			certCondition.Status = metav1.ConditionTrue
			certCondition.Reason = "Valid"
			certCondition.Message = fmt.Sprintf("TLS certificate is valid for %d more days", result.Certificate.DaysUntilExpiry)
		}

		setCondition(&cr.Status.Conditions, certCondition)
	}

	// TLS Profile Compliant condition (OpenShift only)
	if r.ProfileFetcher != nil {
		profileCondition := metav1.Condition{
			Type:               "TLSProfileCompliant",
			LastTransitionTime: now,
		}

		allCompliant := true
		if cr.Status.IngressProfileCompliance != nil && !cr.Status.IngressProfileCompliance.Compliant {
			allCompliant = false
		}
		if cr.Status.APIServerProfileCompliance != nil && !cr.Status.APIServerProfileCompliance.Compliant {
			allCompliant = false
		}
		if cr.Status.KubeletProfileCompliance != nil && !cr.Status.KubeletProfileCompliance.Compliant {
			allCompliant = false
		}

		if allCompliant {
			profileCondition.Status = metav1.ConditionTrue
			profileCondition.Reason = "Compliant"
			profileCondition.Message = "Endpoint meets all OpenShift TLS security profile requirements"
		} else {
			profileCondition.Status = metav1.ConditionFalse
			profileCondition.Reason = "NonCompliant"
			profileCondition.Message = "Endpoint does not meet one or more OpenShift TLS security profile requirements"
		}

		setCondition(&cr.Status.Conditions, profileCondition)
	}
}

// setCondition sets or updates a condition in the condition list
func setCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	for i, existing := range *conditions {
		if existing.Type == condition.Type {
			(*conditions)[i] = condition
			return
		}
	}
	*conditions = append(*conditions, condition)
}

// emitComplianceEvents emits Kubernetes events for compliance changes
func (r *EndpointReconciler) emitComplianceEvents(cr *securityv1alpha1.TLSComplianceReport, oldStatus securityv1alpha1.ComplianceStatus, result *tlscheck.TLSCheckResult) {
	if r.Recorder == nil {
		return
	}

	// Non-compliance detected — only legacy TLS, no modern TLS support
	if cr.Status.ComplianceStatus == securityv1alpha1.ComplianceStatusNonCompliant {
		r.Recorder.Event(cr, corev1.EventTypeWarning, EventReasonTLSNonCompliant,
			fmt.Sprintf("Endpoint %s:%d only supports legacy TLS versions (no TLS 1.2 or 1.3)", cr.Spec.Host, cr.Spec.Port))
	}

	// Compliance status changed
	if oldStatus != "" && oldStatus != cr.Status.ComplianceStatus &&
		oldStatus != securityv1alpha1.ComplianceStatusPending {
		r.Recorder.Event(cr, corev1.EventTypeWarning, EventReasonComplianceChanged,
			fmt.Sprintf("Compliance status changed from %s to %s for %s:%d", oldStatus, cr.Status.ComplianceStatus, cr.Spec.Host, cr.Spec.Port))
	}

	// Certificate expiry warnings
	if result.Certificate != nil {
		if result.Certificate.IsExpired {
			r.Recorder.Event(cr, corev1.EventTypeWarning, EventReasonCertificateExpired,
				fmt.Sprintf("TLS certificate has expired for %s:%d", cr.Spec.Host, cr.Spec.Port))
		} else if result.Certificate.DaysUntilExpiry <= r.CertExpiryDays {
			r.Recorder.Event(cr, corev1.EventTypeWarning, EventReasonCertificateExpiring,
				fmt.Sprintf("TLS certificate for %s:%d expires in %d days", cr.Spec.Host, cr.Spec.Port, result.Certificate.DaysUntilExpiry))
		}
	}
}

// SetupWithManager sets up the controller with the Manager.
// Ingress and Target events are mapped to reconciliation requests that flow
// through the controller-runtime work queue (bounded concurrency, back-pressure).
// Route events use WatchesRawSource because the Route API may not be present.
func (r *EndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Named("endpoint").
		WithOptions(controller.Options{}).
		Watches(&networkingv1.Ingress{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrl.Request {
				ing, ok := obj.(*networkingv1.Ingress)
				if !ok {
					return nil
				}
				r.ReconcileIngress(ctx, ctrl.Request{
					NamespacedName: client.ObjectKeyFromObject(ing),
				})
				return nil
			},
		))

	// Add TLSComplianceTarget watch
	builder = builder.Watches(&securityv1alpha1.TLSComplianceTarget{}, handler.EnqueueRequestsFromMapFunc(
		func(ctx context.Context, obj client.Object) []ctrl.Request {
			target, ok := obj.(*securityv1alpha1.TLSComplianceTarget)
			if !ok {
				return nil
			}
			r.ReconcileTarget(ctx, ctrl.Request{
				NamespacedName: client.ObjectKeyFromObject(target),
			})
			return nil
		},
	))

	// Add Route watch if OpenShift Route API is available
	if r.RouteAPIAvailable {
		routeObj := &unstructured.Unstructured{}
		routeObj.SetGroupVersionKind(routeGVK)

		builder = builder.WatchesRawSource(source.Kind(
			mgr.GetCache(),
			routeObj,
			handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, obj *unstructured.Unstructured) []ctrl.Request {
				r.ReconcileRoute(ctx, ctrl.Request{
					NamespacedName: client.ObjectKeyFromObject(obj),
				})
				return nil
			}),
		))
	}

	return builder.Complete(r)
}

// StartPeriodicScan starts a goroutine that periodically re-checks all endpoints
func (r *EndpointReconciler) StartPeriodicScan(ctx context.Context, interval time.Duration) {
	go func() {
		logger := log.FromContext(ctx).WithName("periodic-scan")
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logger.Info("starting periodic TLS scan")
				start := time.Now()

				if err := r.scanAllEndpoints(ctx); err != nil {
					logger.Error(err, "failed to complete periodic scan")
				}

				duration := time.Since(start)
				metrics.RecordScanCycleDuration(duration.Seconds())
				logger.Info("periodic TLS scan completed", "duration", duration)
			}
		}
	}()
}

// scanPodEndpoints discovers TLS endpoints from all pods in the cluster.
// For hostNetwork pods, the resulting CR is labeled for queryability.
func (r *EndpointReconciler) scanPodEndpoints(ctx context.Context) error {
	logger := log.FromContext(ctx)

	var podList corev1.PodList
	if err := r.List(ctx, &podList); err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	for i := range podList.Items {
		pod := &podList.Items[i]

		if r.isNamespaceFiltered(pod.Namespace) {
			continue
		}

		endpoints := endpoint.ExtractFromPod(pod)
		for _, ep := range endpoints {
			if err := r.processEndpoint(ctx, ep); err != nil {
				logger.Error(err, "failed to process pod endpoint",
					"pod", pod.Name, "namespace", pod.Namespace,
					"host", ep.Host, "port", ep.Port)
				continue
			}

			// Label hostNetwork pod CRs for queryability
			if pod.Spec.HostNetwork {
				crName := endpoint.GenerateCRName(ep)
				var cr securityv1alpha1.TLSComplianceReport
				if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err == nil {
					labels := cr.Labels
					if labels == nil {
						labels = make(map[string]string)
					}
					if labels["tls-compliance.telco.openshift.io/host-network"] != "true" {
						labels["tls-compliance.telco.openshift.io/host-network"] = "true"
						cr.Labels = labels
						if err := r.Update(ctx, &cr); err != nil {
							logger.Error(err, "failed to label hostNetwork CR", "name", crName)
						}
					}
				}
			}
		}
	}

	return nil
}

// scanAllEndpoints re-checks all existing TLSComplianceReport CRs using a worker pool.
func (r *EndpointReconciler) scanAllEndpoints(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// Phase 1: Discover new pod endpoints
	if err := r.scanPodEndpoints(ctx); err != nil {
		logger.Error(err, "pod endpoint scan failed")
		// Continue — don't fail the whole scan
	}

	var crList securityv1alpha1.TLSComplianceReportList
	if err := r.List(ctx, &crList); err != nil {
		return fmt.Errorf("failed to list TLSComplianceReports: %w", err)
	}

	workers := r.Workers
	if workers <= 0 {
		workers = 5
	}

	type scanItem struct {
		name string
		host string
		port int
	}

	items := make(chan scanItem, len(crList.Items))
	for i := range crList.Items {
		cr := &crList.Items[i]
		items <- scanItem{name: cr.Name, host: cr.Spec.Host, port: int(cr.Spec.Port)}
	}
	close(items)

	var wg sync.WaitGroup
	for range min(workers, len(crList.Items)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range items {
				select {
				case <-ctx.Done():
					return
				default:
				}
				r.performTLSCheck(ctx, item.name, item.host, item.port)
			}
		}()
	}
	wg.Wait()

	// Update endpoint count metrics using the already-fetched list
	r.updateEndpointMetrics(ctx, &crList)

	logger.Info("scan completed", "endpoints", len(crList.Items), "workers", workers)
	return nil
}

// updateEndpointMetrics recounts endpoints by compliance status.
// If crList is nil, it fetches from the API; otherwise reuses the provided list.
func (r *EndpointReconciler) updateEndpointMetrics(ctx context.Context, crList *securityv1alpha1.TLSComplianceReportList) {
	if crList == nil {
		crList = &securityv1alpha1.TLSComplianceReportList{}
		if err := r.List(ctx, crList); err != nil {
			return
		}
	}

	counts := map[string]float64{
		string(securityv1alpha1.ComplianceStatusCompliant):         0,
		string(securityv1alpha1.ComplianceStatusNonCompliant):      0,
		string(securityv1alpha1.ComplianceStatusWarning):           0,
		string(securityv1alpha1.ComplianceStatusUnreachable):       0,
		string(securityv1alpha1.ComplianceStatusTimeout):           0,
		string(securityv1alpha1.ComplianceStatusClosed):            0,
		string(securityv1alpha1.ComplianceStatusFiltered):          0,
		string(securityv1alpha1.ComplianceStatusNoTLS):             0,
		string(securityv1alpha1.ComplianceStatusMutualTLSRequired): 0,
		string(securityv1alpha1.ComplianceStatusPending):           0,
		string(securityv1alpha1.ComplianceStatusUnknown):           0,
	}

	for _, cr := range crList.Items {
		status := string(cr.Status.ComplianceStatus)
		if _, ok := counts[status]; ok {
			counts[status]++
		}
	}

	for status, count := range counts {
		metrics.EndpointsTotal.WithLabelValues(status).Set(count)
	}
}

// StartCleanupLoop starts a goroutine that removes CRs for deleted source resources
func (r *EndpointReconciler) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	go func() {
		logger := log.FromContext(ctx).WithName("cleanup")
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.cleanupOrphanedCRs(ctx); err != nil {
					logger.Error(err, "failed to cleanup orphaned CRs")
				}
			}
		}
	}()
}

// sourceKey builds a lookup key "namespace/name" for source resource existence checks.
func sourceKey(namespace, name string) string {
	return namespace + "/" + name
}

// cleanupOrphanedCRs removes TLSComplianceReport CRs whose source resources no longer exist.
// It batches source resource lookups by listing each resource type once, then cross-referencing
// in memory to avoid N+1 API calls.
func (r *EndpointReconciler) cleanupOrphanedCRs(ctx context.Context) error {
	logger := log.FromContext(ctx)

	var crList securityv1alpha1.TLSComplianceReportList
	if err := r.List(ctx, &crList); err != nil {
		return fmt.Errorf("failed to list TLSComplianceReports: %w", err)
	}

	if len(crList.Items) == 0 {
		return nil
	}

	// Build sets of existing source resources by listing each type once
	existingSources := make(map[securityv1alpha1.SourceKind]map[string]bool)

	// Services
	var svcList corev1.ServiceList
	if err := r.List(ctx, &svcList); err != nil {
		logger.Error(err, "failed to list Services for cleanup")
	} else {
		svcSet := make(map[string]bool, len(svcList.Items))
		for i := range svcList.Items {
			svcSet[sourceKey(svcList.Items[i].Namespace, svcList.Items[i].Name)] = true
		}
		existingSources[securityv1alpha1.SourceKindService] = svcSet
	}

	// Ingresses
	var ingList networkingv1.IngressList
	if err := r.List(ctx, &ingList); err != nil {
		logger.Error(err, "failed to list Ingresses for cleanup")
	} else {
		ingSet := make(map[string]bool, len(ingList.Items))
		for i := range ingList.Items {
			ingSet[sourceKey(ingList.Items[i].Namespace, ingList.Items[i].Name)] = true
		}
		existingSources[securityv1alpha1.SourceKindIngress] = ingSet
	}

	// Routes (if available)
	if r.RouteAPIAvailable {
		routeList := &unstructured.UnstructuredList{}
		routeList.SetGroupVersionKind(routeGVK)
		if err := r.List(ctx, routeList); err != nil {
			logger.Error(err, "failed to list Routes for cleanup")
		} else {
			routeSet := make(map[string]bool, len(routeList.Items))
			for i := range routeList.Items {
				routeSet[sourceKey(routeList.Items[i].GetNamespace(), routeList.Items[i].GetName())] = true
			}
			existingSources[securityv1alpha1.SourceKindRoute] = routeSet
		}
	}

	// Pods
	var podList corev1.PodList
	if err := r.List(ctx, &podList); err != nil {
		logger.Error(err, "failed to list Pods for cleanup")
	} else {
		podSet := make(map[string]bool, len(podList.Items))
		for i := range podList.Items {
			podSet[sourceKey(podList.Items[i].Namespace, podList.Items[i].Name)] = true
		}
		existingSources[securityv1alpha1.SourceKindPod] = podSet
	}

	// Targets
	var targetList securityv1alpha1.TLSComplianceTargetList
	if err := r.List(ctx, &targetList); err != nil {
		logger.Error(err, "failed to list TLSComplianceTargets for cleanup")
	} else {
		targetSet := make(map[string]bool, len(targetList.Items))
		for i := range targetList.Items {
			targetSet[sourceKey("cluster-scoped", targetList.Items[i].Name)] = true
		}
		existingSources[securityv1alpha1.SourceKindTarget] = targetSet
	}

	// Check each CR against the in-memory sets
	for i := range crList.Items {
		cr := &crList.Items[i]

		sourceSet, known := existingSources[cr.Spec.SourceKind]
		if !known {
			// Source kind's list failed or is unknown; skip to avoid false deletions
			continue
		}

		key := sourceKey(cr.Spec.SourceNamespace, cr.Spec.SourceName)
		if !sourceSet[key] {
			logger.Info("deleting orphaned TLSComplianceReport", "name", cr.Name,
				"sourceKind", cr.Spec.SourceKind, "sourceName", cr.Spec.SourceName)
			if err := r.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to delete orphaned TLSComplianceReport", "name", cr.Name)
			}
		}
	}

	return nil
}

// isNamespaceFiltered checks if a namespace should be skipped based on
// include and exclude maps. If IncludeNamespaces is set, only those
// namespaces are allowed. Otherwise, ExcludeNamespaces is checked.
// Uses map lookups for O(1) performance on every reconcile event.
func (r *EndpointReconciler) isNamespaceFiltered(namespace string) bool {
	if len(r.IncludeNamespaces) > 0 {
		return !r.IncludeNamespaces[namespace]
	}
	return r.ExcludeNamespaces[namespace]
}

// failureReasonToComplianceStatus maps a TLS check failure reason to the
// corresponding compliance status. Used by both performTLSCheck and updateRetryStatus.
func failureReasonToComplianceStatus(reason tlscheck.FailureReason) securityv1alpha1.ComplianceStatus {
	switch reason {
	case tlscheck.FailureReasonNoTLS:
		return securityv1alpha1.ComplianceStatusNoTLS
	case tlscheck.FailureReasonMutualTLSRequired:
		return securityv1alpha1.ComplianceStatusMutualTLSRequired
	case tlscheck.FailureReasonTimeout:
		return securityv1alpha1.ComplianceStatusTimeout
	case tlscheck.FailureReasonClosed:
		return securityv1alpha1.ComplianceStatusClosed
	case tlscheck.FailureReasonFiltered:
		return securityv1alpha1.ComplianceStatusFiltered
	default:
		return securityv1alpha1.ComplianceStatusUnreachable
	}
}

// ParseNamespaceList parses a comma-separated namespace string into a map for O(1) lookups.
func ParseNamespaceList(namespaces string) map[string]bool {
	result := make(map[string]bool)
	if namespaces == "" {
		return result
	}
	for _, ns := range strings.Split(namespaces, ",") {
		trimmed := strings.TrimSpace(ns)
		if trimmed != "" {
			result[trimmed] = true
		}
	}
	return result
}
