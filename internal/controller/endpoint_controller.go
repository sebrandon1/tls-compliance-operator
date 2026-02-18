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
	"slices"
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

// Event reasons for Kubernetes events
const (
	EventReasonTLSNonCompliant     = "TLSNonCompliant"
	EventReasonComplianceChanged   = "ComplianceChanged"
	EventReasonCertificateExpiring = "CertificateExpiring"
	EventReasonCertificateExpired  = "CertificateExpired"
	EventReasonEndpointDiscovered  = "EndpointDiscovered"
)

// EndpointReconciler reconciles Service, Ingress, and Route resources
type EndpointReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	TLSChecker        tlscheck.Checker
	Recorder          record.EventRecorder
	IncludeNamespaces []string
	ExcludeNamespaces []string
	CertExpiryDays    int
	RouteAPIAvailable bool
	ProfileFetcher    *tlsprofile.Fetcher
	Workers           int
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
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
	route.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "route.openshift.io",
		Version: "v1",
		Kind:    "Route",
	})

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

		// Launch async TLS check
		go r.performTLSCheck(context.Background(), crName, ep.Host, int(ep.Port))

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

// performTLSCheck runs the TLS check and updates the CR status
func (r *EndpointReconciler) performTLSCheck(ctx context.Context, crName, host string, port int) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.TLSChecker == nil {
		return
	}

	// Perform TLS check
	result, checkErr := r.TLSChecker.CheckEndpoint(ctx, host, port)

	// Re-fetch the CR to avoid conflicts
	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get TLSComplianceReport for TLS check update")
		return
	}

	now := metav1.Now()
	cr.Status.LastCheckAt = &now
	cr.Status.CheckCount++

	portStr := fmt.Sprintf("%d", port)

	if checkErr != nil {
		// Use the failure reason from the checker to set a specific status
		switch result.FailureReason {
		case tlscheck.FailureReasonNoTLS:
			cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusNoTLS
		case tlscheck.FailureReasonMutualTLSRequired:
			cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusMutualTLSRequired
		case tlscheck.FailureReasonTimeout:
			cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusTimeout
		case tlscheck.FailureReasonClosed:
			cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusClosed
		case tlscheck.FailureReasonFiltered:
			cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusFiltered
		default:
			cr.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusUnreachable
		}
		cr.Status.ConsecutiveErrors++
		cr.Status.LastError = checkErr.Error()

		if err := r.Status().Update(ctx, &cr); err != nil {
			logger.Error(err, "failed to update TLSComplianceReport after check error")
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

	// Update cipher suites and grades
	cr.Status.CipherSuites = result.CipherSuites
	cr.Status.CipherStrengthGrades = tlscheck.GradeCipherSuites(result.CipherSuites)
	cr.Status.OverallCipherGrade = tlscheck.OverallGrade(result.CipherSuites)

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
	cr.Status.ComplianceStatus = determineComplianceStatus(result)

	// Record metrics
	metrics.RecordCheckDuration(result.CheckDuration.Seconds())
	metrics.RecordVersionSupport(host, portStr, "1.0", result.SupportsTLS10)
	metrics.RecordVersionSupport(host, portStr, "1.1", result.SupportsTLS11)
	metrics.RecordVersionSupport(host, portStr, "1.2", result.SupportsTLS12)
	metrics.RecordVersionSupport(host, portStr, "1.3", result.SupportsTLS13)

	// Update conditions
	r.updateConditions(&cr, result)

	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "failed to update TLSComplianceReport with check results")
		return
	}

	// Emit events
	r.emitComplianceEvents(&cr, oldComplianceStatus, result)
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
func (r *EndpointReconciler) updateConditions(cr *securityv1alpha1.TLSComplianceReport, result *tlscheck.TLSCheckResult) {
	now := metav1.Now()

	// TLS Compliant condition
	complianceCondition := metav1.Condition{
		Type:               "TLSCompliant",
		LastTransitionTime: now,
	}

	switch determineComplianceStatus(result) {
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

// SetupWithManager sets up the controller with the Manager
func (r *EndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Named("endpoint").
		WithOptions(controller.Options{}).
		Watches(&networkingv1.Ingress{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []ctrl.Request {
				ing, ok := obj.(*networkingv1.Ingress)
				if !ok {
					return nil
				}
				go r.ReconcileIngress(context.Background(), ctrl.Request{
					NamespacedName: client.ObjectKeyFromObject(ing),
				})
				return nil
			},
		))

	// Add TLSComplianceTarget watch
	builder = builder.Watches(&securityv1alpha1.TLSComplianceTarget{}, handler.EnqueueRequestsFromMapFunc(
		func(_ context.Context, obj client.Object) []ctrl.Request {
			target, ok := obj.(*securityv1alpha1.TLSComplianceTarget)
			if !ok {
				return nil
			}
			go r.ReconcileTarget(context.Background(), ctrl.Request{
				NamespacedName: client.ObjectKeyFromObject(target),
			})
			return nil
		},
	))

	// Add Route watch if OpenShift Route API is available
	if r.RouteAPIAvailable {
		routeGVK := schema.GroupVersionKind{
			Group:   "route.openshift.io",
			Version: "v1",
			Kind:    "Route",
		}

		routeObj := &unstructured.Unstructured{}
		routeObj.SetGroupVersionKind(routeGVK)

		builder = builder.WatchesRawSource(source.Kind(
			mgr.GetCache(),
			routeObj,
			handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, obj *unstructured.Unstructured) []ctrl.Request {
				go r.ReconcileRoute(context.Background(), ctrl.Request{
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

// scanAllEndpoints re-checks all existing TLSComplianceReport CRs using a worker pool.
func (r *EndpointReconciler) scanAllEndpoints(ctx context.Context) error {
	logger := log.FromContext(ctx)

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

	// Update endpoint count metrics
	r.updateEndpointMetrics(ctx)

	logger.Info("scan completed", "endpoints", len(crList.Items), "workers", workers)
	return nil
}

// updateEndpointMetrics recounts endpoints by compliance status
func (r *EndpointReconciler) updateEndpointMetrics(ctx context.Context) {
	var crList securityv1alpha1.TLSComplianceReportList
	if err := r.List(ctx, &crList); err != nil {
		return
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

// cleanupOrphanedCRs removes TLSComplianceReport CRs whose source resources no longer exist
func (r *EndpointReconciler) cleanupOrphanedCRs(ctx context.Context) error {
	logger := log.FromContext(ctx)

	var crList securityv1alpha1.TLSComplianceReportList
	if err := r.List(ctx, &crList); err != nil {
		return fmt.Errorf("failed to list TLSComplianceReports: %w", err)
	}

	for i := range crList.Items {
		cr := &crList.Items[i]

		exists, err := r.sourceResourceExists(ctx, cr.Spec)
		if err != nil {
			logger.Error(err, "error checking source resource", "name", cr.Name)
			continue
		}

		if !exists {
			logger.Info("deleting orphaned TLSComplianceReport", "name", cr.Name,
				"sourceKind", cr.Spec.SourceKind, "sourceName", cr.Spec.SourceName)
			if err := r.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to delete orphaned TLSComplianceReport", "name", cr.Name)
			}
		}
	}

	return nil
}

// sourceResourceExists checks if the source resource for a CR still exists
func (r *EndpointReconciler) sourceResourceExists(ctx context.Context, spec securityv1alpha1.TLSComplianceReportSpec) (bool, error) {
	key := client.ObjectKey{
		Namespace: spec.SourceNamespace,
		Name:      spec.SourceName,
	}

	var err error
	switch spec.SourceKind {
	case securityv1alpha1.SourceKindService:
		var svc corev1.Service
		err = r.Get(ctx, key, &svc)
	case securityv1alpha1.SourceKindIngress:
		var ing networkingv1.Ingress
		err = r.Get(ctx, key, &ing)
	case securityv1alpha1.SourceKindRoute:
		route := &unstructured.Unstructured{}
		route.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "route.openshift.io",
			Version: "v1",
			Kind:    "Route",
		})
		err = r.Get(ctx, key, route)
	case securityv1alpha1.SourceKindTarget:
		var target securityv1alpha1.TLSComplianceTarget
		err = r.Get(ctx, client.ObjectKey{Name: spec.SourceName}, &target)
	default:
		return false, fmt.Errorf("unknown source kind: %s", spec.SourceKind)
	}

	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// isNamespaceFiltered checks if a namespace should be skipped based on
// include and exclude lists. If IncludeNamespaces is set, only those
// namespaces are allowed. Otherwise, ExcludeNamespaces is checked.
func (r *EndpointReconciler) isNamespaceFiltered(namespace string) bool {
	if len(r.IncludeNamespaces) > 0 {
		return !slices.Contains(r.IncludeNamespaces, namespace)
	}
	return slices.Contains(r.ExcludeNamespaces, namespace)
}
