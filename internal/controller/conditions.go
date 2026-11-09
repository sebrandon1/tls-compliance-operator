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
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
	"github.com/sebrandon1/tls-compliance-operator/internal/notify"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlsprofile"
)

func (r *EndpointReconciler) updateTargetStatus(ctx context.Context, targetName, reportName, complianceStatus, errMsg string) {
	logger := log.FromContext(ctx)

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var target securityv1alpha1.TLSComplianceTarget
		if err := r.Get(ctx, client.ObjectKey{Name: targetName}, &target); err != nil {
			return err
		}

		now := metav1.Now()
		target.Status.LastScannedAt = &now
		target.Status.ReportName = reportName

		if errMsg != "" {
			target.Status.ComplianceStatus = ""
			target.Status.Message = errMsg
			apimeta.SetStatusCondition(&target.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				ObservedGeneration: target.Generation,
				LastTransitionTime: now,
				Reason:             "ScanFailed",
				Message:            errMsg,
			})
		} else {
			target.Status.ComplianceStatus = securityv1alpha1.ComplianceStatus(complianceStatus)
			target.Status.Message = ""
			apimeta.SetStatusCondition(&target.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: target.Generation,
				LastTransitionTime: now,
				Reason:             "ScanComplete",
				Message:            fmt.Sprintf("Report %s generated", reportName),
			})
		}

		return r.Status().Update(ctx, &target)
	}); err != nil {
		logger.Error(err, "failed to update TLSComplianceTarget status", "target", targetName)
	}
}

func (r *EndpointReconciler) recordCheckMetrics(ctx context.Context, crName, host string, port int, result *tlscheck.TLSCheckResult, outcome *checkOutcome) {
	portStr := fmt.Sprintf("%d", port)

	metrics.RecordCheckDuration(result.CheckDuration.Seconds())
	if r.MetricsPerEndpoint {
		metrics.RecordVersionSupport(host, portStr, "ssl3.0", result.SupportsSSL30)
		metrics.RecordVersionSupport(host, portStr, "1.0", result.SupportsTLS10)
		metrics.RecordVersionSupport(host, portStr, "1.1", result.SupportsTLS11)
		metrics.RecordVersionSupport(host, portStr, "1.2", result.SupportsTLS12)
		metrics.RecordVersionSupport(host, portStr, "1.3", result.SupportsTLS13)
		metrics.RecordForwardSecrecy(host, portStr, outcome.forwardSecrecy)
		metrics.RecordPQCReadiness(host, portStr, outcome.pqcReadiness)
		metrics.RecordCipherGrade(host, portStr, outcome.overallGrade)
		if result.Certificate != nil {
			metrics.RecordCertExpiry(host, portStr, float64(result.Certificate.DaysUntilExpiry))
		}
	}

	var cr securityv1alpha1.TLSComplianceReport
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err == nil {
		r.emitComplianceEvents(&cr, outcome.oldComplianceStatus, outcome.oldPQCReadiness, result)
		r.notifyStatusChange(ctx, &cr, outcome.oldComplianceStatus, outcome.oldPQCReadiness)
	}
}

// complianceStatusChanged reports whether a compliance transition is
// notification-worthy. The first measurement of an endpoint (empty or Pending
// old status) is not a change.
func complianceStatusChanged(oldStatus, newStatus securityv1alpha1.ComplianceStatus) bool {
	return oldStatus != "" && oldStatus != securityv1alpha1.ComplianceStatusPending && oldStatus != newStatus
}

// pqcReadinessChanged reports whether a post-quantum readiness transition
// happened, ignoring the first measurement.
func pqcReadinessChanged(oldReadiness, newReadiness securityv1alpha1.PQCReadiness) bool {
	return oldReadiness != "" && oldReadiness != newReadiness
}

// notifyStatusChange posts status transitions to the configured webhooks.
// Delivery runs off the reconcile path so a slow or unavailable receiver never
// holds a worker or fails a scan.
func (r *EndpointReconciler) notifyStatusChange(
	ctx context.Context, cr *securityv1alpha1.TLSComplianceReport,
	oldStatus securityv1alpha1.ComplianceStatus, oldPQCReadiness securityv1alpha1.PQCReadiness,
) {
	if r.Notifier == nil {
		return
	}
	if !complianceStatusChanged(oldStatus, cr.Status.ComplianceStatus) &&
		!pqcReadinessChanged(oldPQCReadiness, cr.Status.PQCReadiness) {
		return
	}

	event := notify.Event{
		ReportName: cr.Name,
		Namespace:  cr.Namespace,
		Host:       cr.Spec.Host,
		Port:       cr.Spec.Port,
		OldStatus:  string(oldStatus),
		NewStatus:  string(cr.Status.ComplianceStatus),
		OldPQC:     string(oldPQCReadiness),
		NewPQC:     string(cr.Status.PQCReadiness),
		Timestamp:  time.Now().UTC(),
	}

	logger := log.FromContext(ctx).WithName("notify")
	go r.Notifier.Deliver(context.WithoutCancel(ctx), logger, &event)
}

// updateRetryStatus updates the CR with intermediate retry status information
func (r *EndpointReconciler) updateRetryStatus(ctx context.Context, crName string, retryCount int, retryDelay time.Duration, reason tlscheck.FailureReason, checkErr error) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if err := r.updateStatusWithRetry(ctx, crName, func(cr *securityv1alpha1.TLSComplianceReport) {
		nextRetry := metav1.NewTime(time.Now().Add(retryDelay))
		cr.Status.RetryCount = retryCount
		cr.Status.NextRetryAt = &nextRetry
		cr.Status.NextScanAt = &nextRetry
		cr.Status.LastError = checkErr.Error()
		cr.Status.ConsecutiveErrors++
		cr.Status.ComplianceStatus = failureReasonToComplianceStatus(reason)
	}); err != nil {
		logger.Error(err, "failed to update TLSComplianceReport retry status")
	}
}

// checkProfileCompliance evaluates the endpoint against OpenShift TLS security
// profiles if a ProfileFetcher is configured, and against the built-in profile
// selected by the source TLSComplianceTarget, if any. Populates the per-profile
// compliance fields on the CR status.
func (r *EndpointReconciler) checkProfileCompliance(ctx context.Context, cr *securityv1alpha1.TLSComplianceReport, result *tlscheck.TLSCheckResult) {
	if r.ProfileFetcher != nil {
		for component, profile := range r.ProfileFetcher.GetAllProfiles() {
			compResult := checkAgainstProfile(&profile, result)
			crdResult := profileResultToCRD(&compResult)

			if r.MetricsPerEndpoint {
				metrics.RecordProfileCompliance(
					cr.Spec.Host, strconv.Itoa(int(cr.Spec.Port)),
					string(component), compResult.ProfileType, compResult.Compliant,
				)
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

	selected := r.targetProfile(ctx, cr)
	if selected == "" {
		return
	}
	profile, ok := tlsprofile.PredefinedProfiles[tlsprofile.ProfileType(selected)]
	if !ok {
		return
	}
	compResult := checkAgainstProfile(&profile, result)
	cr.Status.SelectedProfileCompliance = profileResultToCRD(&compResult)
	if r.MetricsPerEndpoint {
		metrics.RecordProfileCompliance(
			cr.Spec.Host, strconv.Itoa(int(cr.Spec.Port)),
			"Selected", compResult.ProfileType, compResult.Compliant,
		)
	}
}

// checkAgainstProfile evaluates a TLS check result against one profile.
func checkAgainstProfile(profile *tlsprofile.Profile, result *tlscheck.TLSCheckResult) tlsprofile.ComplianceResult {
	return tlsprofile.CheckCompliance(
		profile,
		result.SupportsTLS10,
		result.SupportsTLS11,
		result.SupportsTLS12,
		result.SupportsTLS13,
		result.CipherSuites,
		result.NegotiatedCurves,
	)
}

// profileResultToCRD converts a compliance result into its CR status form.
func profileResultToCRD(compResult *tlsprofile.ComplianceResult) *securityv1alpha1.TLSProfileComplianceResult {
	return &securityv1alpha1.TLSProfileComplianceResult{
		ProfileType:       compResult.ProfileType,
		Compliant:         compResult.Compliant,
		MinTLSVersionMet:  compResult.MinTLSVersionMet,
		DisallowedCiphers: compResult.DisallowedCiphers,
		GroupsCompliant:   compResult.GroupsCompliant,
		DisallowedGroups:  compResult.DisallowedGroups,
	}
}

// updateConditions sets Kubernetes conditions based on check results
func (r *EndpointReconciler) updateConditions(cr *securityv1alpha1.TLSComplianceReport, complianceStatus securityv1alpha1.ComplianceStatus, result *tlscheck.TLSCheckResult) {
	now := metav1.Now()

	complianceCondition := metav1.Condition{
		Type:               "TLSCompliant",
		ObservedGeneration: cr.Generation,
		LastTransitionTime: now,
	}

	switch complianceStatus {
	case securityv1alpha1.ComplianceStatusCompliant:
		complianceCondition.Status = metav1.ConditionTrue
		complianceCondition.Reason = "Compliant"
		complianceCondition.Message = "Endpoint supports modern TLS (1.2 or 1.3)"
	case securityv1alpha1.ComplianceStatusWarning:
		complianceCondition.Status = metav1.ConditionTrue
		complianceCondition.Reason = "Warning"
		complianceCondition.Message = "Endpoint supports modern TLS but also allows legacy versions"
	case securityv1alpha1.ComplianceStatusNonCompliant:
		complianceCondition.Status = metav1.ConditionFalse
		complianceCondition.Reason = "NonCompliant"
		complianceCondition.Message = "Endpoint only supports legacy TLS versions (no TLS 1.2 or 1.3)"
	default:
		complianceCondition.Status = metav1.ConditionUnknown
		complianceCondition.Reason = "Unknown"
		complianceCondition.Message = "TLS compliance status could not be determined"
	}

	apimeta.SetStatusCondition(&cr.Status.Conditions, complianceCondition)

	if result.Certificate != nil {
		certCondition := metav1.Condition{
			Type:               "CertificateValid",
			ObservedGeneration: cr.Generation,
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

		apimeta.SetStatusCondition(&cr.Status.Conditions, certCondition)
	}

	pqcCondition := metav1.Condition{
		Type:               "PQCCompliant",
		ObservedGeneration: cr.Generation,
		LastTransitionTime: now,
	}

	switch cr.Status.PQCReadiness {
	case securityv1alpha1.PQCReadinessPQCReady:
		pqcCondition.Status = metav1.ConditionTrue
		pqcCondition.Reason = "PQCReady"
		if result.MLKEMSupported {
			pqcCondition.Message = "Endpoint supports TLS 1.3 with hybrid ML-KEM key exchange (verified by active probe)"
		} else {
			pqcCondition.Message = "Endpoint supports TLS 1.3 with hybrid ML-KEM key exchange"
		}
	case securityv1alpha1.PQCReadinessTLS13Capable:
		pqcCondition.Status = metav1.ConditionFalse
		pqcCondition.Reason = "TLS13Capable"
		if r.FIPSEnabled {
			pqcCondition.Message = "Endpoint supports TLS 1.3 but has not negotiated a post-quantum key exchange (FIPS mode active, ML-KEM unavailable)"
		} else {
			pqcCondition.Message = "Endpoint supports TLS 1.3 but has not negotiated a post-quantum key exchange"
		}
	case securityv1alpha1.PQCReadinessLegacyTLS:
		pqcCondition.Status = metav1.ConditionFalse
		pqcCondition.Reason = "LegacyTLS"
		pqcCondition.Message = "Endpoint only supports TLS 1.2 or older, no path to post-quantum cryptography"
	default:
		pqcCondition.Status = metav1.ConditionUnknown
		pqcCondition.Reason = "NoPQC"
		pqcCondition.Message = "No TLS detected on endpoint"
	}

	apimeta.SetStatusCondition(&cr.Status.Conditions, pqcCondition)

	if r.ProfileFetcher != nil {
		profileCondition := metav1.Condition{
			Type:               "TLSProfileCompliant",
			ObservedGeneration: cr.Generation,
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

		apimeta.SetStatusCondition(&cr.Status.Conditions, profileCondition)
	}
}

// emitComplianceEvents emits Kubernetes events for compliance changes
func (r *EndpointReconciler) emitComplianceEvents(cr *securityv1alpha1.TLSComplianceReport, oldStatus securityv1alpha1.ComplianceStatus, oldPQCReadiness securityv1alpha1.PQCReadiness, result *tlscheck.TLSCheckResult) {
	if r.Recorder == nil {
		return
	}

	if cr.Status.ComplianceStatus == securityv1alpha1.ComplianceStatusWarning {
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, EventReasonTLSWarning, EventActionScan,
			"Endpoint %s supports modern TLS but also allows legacy versions", hostPort(cr.Spec.Host, cr.Spec.Port))
	}

	if cr.Status.ComplianceStatus == securityv1alpha1.ComplianceStatusNonCompliant {
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, EventReasonTLSNonCompliant, EventActionScan,
			"Endpoint %s only supports legacy TLS versions (no TLS 1.2 or 1.3)", hostPort(cr.Spec.Host, cr.Spec.Port))
	}

	if complianceStatusChanged(oldStatus, cr.Status.ComplianceStatus) {
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, EventReasonComplianceChanged, EventActionScan,
			"Compliance status changed from %s to %s for %s", oldStatus, cr.Status.ComplianceStatus, hostPort(cr.Spec.Host, cr.Spec.Port))
	}

	if pqcReadinessChanged(oldPQCReadiness, cr.Status.PQCReadiness) {
		if cr.Status.PQCReadiness == securityv1alpha1.PQCReadinessPQCReady {
			r.Recorder.Eventf(cr, nil, corev1.EventTypeNormal, EventReasonPQCReady, EventActionScan,
				"Endpoint %s is now post-quantum ready (TLS 1.3 + hybrid ML-KEM)", hostPort(cr.Spec.Host, cr.Spec.Port))
		} else {
			fipsSuffix := ""
			if r.FIPSEnabled && cr.Status.PQCReadiness == securityv1alpha1.PQCReadinessTLS13Capable {
				fipsSuffix = " (FIPS mode active, ML-KEM unavailable)"
			}
			r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, EventReasonPQCNotReady, EventActionScan,
				"PQC readiness changed from %s to %s for %s%s", oldPQCReadiness, cr.Status.PQCReadiness, hostPort(cr.Spec.Host, cr.Spec.Port), fipsSuffix)
		}
	}

	if result.Certificate != nil {
		if result.Certificate.IsExpired {
			r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, EventReasonCertificateExpired, EventActionScan,
				"TLS certificate has expired for %s", hostPort(cr.Spec.Host, cr.Spec.Port))
		} else if result.Certificate.DaysUntilExpiry <= r.CertExpiryDays {
			r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, EventReasonCertificateExpiring, EventActionScan,
				"TLS certificate for %s expires in %d days", hostPort(cr.Spec.Host, cr.Spec.Port), result.Certificate.DaysUntilExpiry)
		}
	}
}
