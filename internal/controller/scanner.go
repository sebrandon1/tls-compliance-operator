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
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

// processEndpoint creates or updates a TLSComplianceReport CR for an endpoint
func (r *EndpointReconciler) processEndpoint(ctx context.Context, ep *endpoint.Endpoint) error {
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
				SourceKind:      ep.SourceKind,
				SourceNamespace: ep.SourceNamespace,
				SourceName:      ep.SourceName,
			},
		}

		if err := r.Create(ctx, cr); err != nil {
			return fmt.Errorf("failed to create TLSComplianceReport: %w", err)
		}

		cr.Status = securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusPending,
			FirstSeenAt:      &now,
			LastSeenAt:       &now,
		}
		apimeta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
			Type:               "Available",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: cr.Generation,
			LastTransitionTime: now,
			Reason:             "EndpointDiscovered",
			Message:            fmt.Sprintf("Endpoint %s discovered from %s/%s", hostPort(ep.Host, ep.Port), ep.SourceNamespace, ep.SourceName),
		})
		if err := r.Status().Update(ctx, cr); err != nil {
			return fmt.Errorf("failed to update TLSComplianceReport status: %w", err)
		}

		logger.Info("created TLSComplianceReport", "name", crName, "host", ep.Host, "port", ep.Port)

		if r.Recorder != nil {
			r.Recorder.Eventf(cr, nil, corev1.EventTypeNormal, EventReasonEndpointDiscovered, EventActionScan,
				"Discovered TLS endpoint %s from %s %s/%s", hostPort(ep.Host, ep.Port), ep.SourceKind, ep.SourceNamespace, ep.SourceName)
		}
		metrics.RecordEndpointDiscovered(string(ep.SourceKind), ep.SourceNamespace)

		if err := r.tryAsyncCheck(crName, ep.Host, int(ep.Port), ep.SourceNamespace); err != nil {
			logger.V(1).Info("TLS check deferred, requeuing", "host", ep.Host, "port", ep.Port)
			return err
		}

		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get TLSComplianceReport: %w", err)
	}

	if err := r.updateStatusWithRetry(ctx, crName, func(cr *securityv1alpha1.TLSComplianceReport) {
		cr.Status.LastSeenAt = &now
	}); err != nil {
		return fmt.Errorf("failed to update TLSComplianceReport LastSeenAt: %w", err)
	}

	if existingCR.Status.ComplianceStatus == securityv1alpha1.ComplianceStatusPending && existingCR.Status.CheckCount == 0 {
		if err := r.tryAsyncCheck(crName, ep.Host, int(ep.Port), ep.SourceNamespace); err != nil {
			logger.V(1).Info("TLS check deferred for pending CR, requeuing", "host", ep.Host, "port", ep.Port)
			return err
		}
	}

	return nil
}

func (r *EndpointReconciler) tryAsyncCheck(crName, host string, port int, namespace string) error {
	if r.skipIfCircuitOpen(crName) {
		return nil
	}
	r.initCheckSemaphore()
	select {
	case r.checkSem <- struct{}{}:
		metrics.RecordWorkerAcquire()
		go func() {
			defer func() {
				<-r.checkSem
				metrics.RecordWorkerRelease()
			}()
			// Reconcile context is cancelled when Reconcile returns, so async
			// probes must use ManagerCtx (process lifetime). Wrap it with a
			// timeout so a hung CheckEndpoint cannot hold a worker until shutdown.
			ctx, cancel := context.WithTimeout(r.managerCtx(), r.asyncCheckTimeout())
			defer cancel()
			r.performTLSCheck(ctx, crName, host, port, namespace, true)
		}()
		return nil
	default:
		return errWorkersBusy
	}
}

func (r *EndpointReconciler) managerCtx() context.Context {
	if r.ManagerCtx != nil {
		return r.ManagerCtx
	}
	return context.Background()
}

func (r *EndpointReconciler) asyncCheckTimeout() time.Duration {
	if r.checkTimeout > 0 {
		return r.checkTimeout
	}
	attempts := 1 + r.MaxRetries
	if attempts < 1 {
		attempts = 1
	}
	backoffCap := r.MaxBackoff
	if backoffCap <= 0 {
		backoffCap = 5 * time.Minute
	}
	// Cover each CheckEndpoint attempt plus backoff between them so the
	// deadline cannot cancel a still-valid retry.
	return time.Duration(attempts)*tlscheck.DefaultTimeout + time.Duration(attempts-1)*backoffCap
}

func (r *EndpointReconciler) performTLSCheck(ctx context.Context, crName, host string, port int, namespace string, holdsSemaphore bool) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.TLSChecker == nil {
		return
	}
	if r.skipIfCircuitOpen(crName) {
		return
	}

	if limiter := r.getNamespaceLimiter(namespace); limiter != nil {
		if err := limiter.Wait(ctx); err != nil {
			logger.V(1).Info("namespace rate limiter cancelled", "namespace", namespace, "error", err)
			return
		}
	}

	result, checkErr := r.retryTLSCheck(ctx, crName, host, port, holdsSemaphore)
	if result == nil && checkErr == nil {
		return
	}

	outcome := r.applyCheckResult(ctx, crName, host, port, result, checkErr)
	if outcome != nil {
		r.recordCheckMetrics(ctx, crName, host, port, result, outcome)
	}
}

type checkOutcome struct {
	oldComplianceStatus securityv1alpha1.ComplianceStatus
	oldPQCReadiness     securityv1alpha1.PQCReadiness
	forwardSecrecy      bool
	pqcReadiness        securityv1alpha1.PQCReadiness
}

func (r *EndpointReconciler) retryTLSCheck(ctx context.Context, crName, host string, port int, holdsSemaphore bool) (*tlscheck.TLSCheckResult, error) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	maxAttempts := 1 + r.MaxRetries
	retryBackoff := r.RetryBackoff
	if retryBackoff <= 0 {
		retryBackoff = 30 * time.Second
	}
	maxBackoff := r.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 5 * time.Minute
	}
	backoff := wait.Backoff{
		Duration: retryBackoff,
		Factor:   2,
		Jitter:   0.25,
		Steps:    maxAttempts,
		Cap:      maxBackoff,
	}

	var result *tlscheck.TLSCheckResult
	var checkErr error

	for attempt := range maxAttempts {
		result, checkErr = r.TLSChecker.CheckEndpoint(ctx, host, port)

		if checkErr == nil {
			break
		}

		if result == nil || !result.FailureReason.IsTransient() {
			break
		}

		if attempt < maxAttempts-1 {
			retryDelay := backoff.Step()

			logger.Info("transient TLS check failure, retrying",
				"attempt", attempt+1,
				"maxAttempts", maxAttempts,
				"reason", string(result.FailureReason),
				"retryDelay", retryDelay)

			metrics.RecordRetry(string(result.FailureReason))

			r.updateRetryStatus(ctx, crName, attempt+1, retryDelay, result.FailureReason, checkErr)

			if holdsSemaphore {
				<-r.checkSem
				metrics.RecordWorkerRelease()
			}

			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				if holdsSemaphore {
					r.checkSem <- struct{}{}
					metrics.RecordWorkerAcquire()
				}
				return nil, nil
			case <-timer.C:
			}

			if holdsSemaphore {
				r.checkSem <- struct{}{}
				metrics.RecordWorkerAcquire()
			}
		}
	}

	return result, checkErr
}

func (r *EndpointReconciler) applyCheckResult(ctx context.Context, crName, host string, port int, result *tlscheck.TLSCheckResult, checkErr error) *checkOutcome {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if checkErr != nil {
		var failReason tlscheck.FailureReason
		if result != nil {
			failReason = result.FailureReason
		}
		reason := "unknown"
		if failReason != "" {
			reason = string(failReason)
		}
		metrics.RecordCheckError(reason)

		if isCircuitFailure(failReason) {
			r.recordCircuitFailure(crName)
		} else {
			r.recordCircuitSuccess(crName)
		}

		if err := r.updateStatusWithRetry(ctx, crName, func(cr *securityv1alpha1.TLSComplianceReport) {
			now := metav1.Now()
			cr.Status.LastCheckAt = &now
			cr.Status.CheckCount++
			cr.Status.RetryCount = 0
			cr.Status.NextRetryAt = nil

			if result != nil {
				cr.Status.TLSVersions = securityv1alpha1.TLSVersionSupport{
					SSL30: result.SupportsSSL30,
					TLS10: result.SupportsTLS10,
					TLS11: result.SupportsTLS11,
					TLS12: result.SupportsTLS12,
					TLS13: result.SupportsTLS13,
				}
				if result.CheckDuration > 0 {
					cr.Status.ScanDuration = result.CheckDuration.String()
				}
			}

			cr.Status.ComplianceStatus = failureReasonToComplianceStatus(failReason)
			cr.Status.ConsecutiveErrors++
			cr.Status.LastError = checkErr.Error()
		}); err != nil {
			logger.Error(err, "failed to update TLSComplianceReport after check error")
		}

		if failReason.IsTransient() && r.MaxRetries > 0 {
			metrics.RecordRetriesExhausted()
			if r.Recorder != nil {
				var cr securityv1alpha1.TLSComplianceReport
				if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err == nil {
					r.Recorder.Eventf(&cr, nil, corev1.EventTypeWarning, EventReasonRetryExhausted, EventActionScan,
						"TLS check retries exhausted for %s after %d attempts: %s",
						hostPort(host, int32(port)), 1+r.MaxRetries, failReason)
				}
			}
		}
		return nil
	}

	cipherGrades := tlscheck.GradeCipherSuites(result.CipherSuites)
	overallGrade := tlscheck.OverallGrade(result.CipherSuites, cipherGrades)
	forwardSecrecy := tlscheck.AllCiphersHaveForwardSecrecy(result.CipherSuites)
	keyExchangeTypes := tlscheck.KeyExchangeTypes(result.CipherSuites)
	pqcReadiness := determinePQCReadiness(result)
	complianceStatus := determineComplianceStatus(result)

	r.recordCircuitSuccess(crName)

	var oldComplianceStatus securityv1alpha1.ComplianceStatus
	var oldPQCReadiness securityv1alpha1.PQCReadiness

	if err := r.updateStatusWithRetry(ctx, crName, func(cr *securityv1alpha1.TLSComplianceReport) {
		now := metav1.Now()
		cr.Status.LastCheckAt = &now
		cr.Status.CheckCount++
		cr.Status.RetryCount = 0
		cr.Status.NextRetryAt = nil
		cr.Status.ConsecutiveErrors = 0
		cr.Status.LastError = ""
		if result.CheckDuration > 0 {
			cr.Status.ScanDuration = result.CheckDuration.String()
		}

		oldComplianceStatus = cr.Status.ComplianceStatus
		oldPQCReadiness = cr.Status.PQCReadiness

		cr.Status.TLSVersions = securityv1alpha1.TLSVersionSupport{
			SSL30: result.SupportsSSL30,
			TLS10: result.SupportsTLS10,
			TLS11: result.SupportsTLS11,
			TLS12: result.SupportsTLS12,
			TLS13: result.SupportsTLS13,
		}

		cr.Status.CipherSuites = result.CipherSuites
		cr.Status.CipherStrengthGrades = cipherGrades
		cr.Status.OverallCipherGrade = overallGrade
		cr.Status.ForwardSecrecy = forwardSecrecy
		cr.Status.KeyExchangeTypes = keyExchangeTypes
		cr.Status.ALPNProtocols = result.ALPNProtocols
		cr.Status.NegotiatedCurves = result.NegotiatedCurves
		cr.Status.PQCReadiness = pqcReadiness
		cr.Status.QuantumReady = pqcReadiness == securityv1alpha1.PQCReadinessPQCReady
		cr.Status.MLKEMSupported = result.MLKEMSupported
		cr.Status.FIPSDetected = r.FIPSEnabled

		if result.Certificate != nil {
			notBefore := metav1.NewTime(result.Certificate.NotBefore)
			notAfter := metav1.NewTime(result.Certificate.NotAfter)
			hostnameMatch := result.Certificate.HostnameMatch
			cr.Status.CertificateInfo = &securityv1alpha1.CertificateInfo{
				Issuer:             result.Certificate.Issuer,
				Subject:            result.Certificate.Subject,
				NotBefore:          &notBefore,
				NotAfter:           &notAfter,
				DNSNames:           result.Certificate.DNSNames,
				IsExpired:          result.Certificate.IsExpired,
				DaysUntilExpiry:    result.Certificate.DaysUntilExpiry,
				HostnameMatch:      &hostnameMatch,
				ChainLength:        result.Certificate.ChainLength,
				PublicKeyAlgorithm: result.Certificate.PublicKeyAlgorithm,
				PublicKeyBits:      result.Certificate.PublicKeyBits,
				SignatureAlgorithm: result.Certificate.SignatureAlgorithm,
				SerialNumber:       result.Certificate.SerialNumber,
				Fingerprint:        result.Certificate.Fingerprint,
				IPAddresses:        result.Certificate.IPAddresses,
			}
		}

		if r.ProfileFetcher != nil {
			cr.Status.TLSAdherence = r.ProfileFetcher.GetAdherence()
		}
		r.checkProfileCompliance(cr, result)
		cr.Status.ComplianceStatus = complianceStatus
		r.updateConditions(cr, complianceStatus, result)
	}); err != nil {
		logger.Error(err, "failed to update TLSComplianceReport with check results")
		return nil
	}

	return &checkOutcome{
		oldComplianceStatus: oldComplianceStatus,
		oldPQCReadiness:     oldPQCReadiness,
		forwardSecrecy:      forwardSecrecy,
		pqcReadiness:        pqcReadiness,
	}
}

// StartPeriodicScan starts a goroutine that scans all endpoints after leader
// election completes, then re-checks on every tick of the configured interval.
// The elected channel should come from mgr.Elected() to ensure the informer
// cache is synced before scanning.
func (r *EndpointReconciler) StartPeriodicScan(ctx context.Context, interval time.Duration, elected <-chan struct{}) {
	go func() {
		logger := log.FromContext(ctx).WithName("periodic-scan")

		if elected != nil {
			logger.Info("waiting for leader election before initial scan")
			select {
			case <-ctx.Done():
				return
			case <-elected:
				logger.Info("leader election complete, starting initial scan")
			}
		}

		logger.Info("running initial TLS scan of all endpoints")
		scanErr := r.runScanCycleWithError(ctx, logger)

		if r.RunOnce {
			logger.Info("run-once mode: scan complete, signaling done")
			r.RunOnceDone <- scanErr
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = r.runScanCycleWithError(ctx, logger)
			}
		}
	}()
}

func (r *EndpointReconciler) runScanCycleWithError(ctx context.Context, logger logr.Logger) error {
	logger.Info("starting periodic TLS scan")
	start := time.Now()

	err := r.scanAllEndpoints(ctx)
	if err != nil {
		logger.Error(err, "failed to complete periodic scan")
		metrics.RecordScanCycleError()
	} else {
		metrics.RecordScanCycleCompleted()
	}

	duration := time.Since(start)
	metrics.RecordScanCycleDuration(duration.Seconds())
	logger.Info("periodic TLS scan finished", "duration", duration, "success", err == nil)
	return err
}

// scanPodEndpoints lists all pods and processes them as TLS endpoints.
// For hostNetwork pods, the resulting CR is labeled for queryability.
func (r *EndpointReconciler) scanPodEndpoints(ctx context.Context) error {
	logger := log.FromContext(ctx)

	var podList corev1.PodList
	return paginatedList(ctx, r.apiReader(), &podList, func() {
		for i := range podList.Items {
			pod := &podList.Items[i]

			if r.isNamespaceFiltered(pod.Namespace) {
				continue
			}

			if endpoint.ShouldSkipResource(pod.Annotations) {
				continue
			}

			endpoints := endpoint.ExtractFromPod(pod)
			for j := range endpoints {
				if err := r.processEndpoint(ctx, &endpoints[j]); err != nil {
					logger.Error(err, "failed to process pod endpoint",
						"pod", pod.Name, "namespace", pod.Namespace,
						"host", endpoints[j].Host, "port", endpoints[j].Port)
					continue
				}

				if pod.Spec.HostNetwork {
					crName := endpoint.GenerateCRName(&endpoints[j])
					if err := r.updateWithRetry(ctx, crName, func(cr *securityv1alpha1.TLSComplianceReport) {
						labels := cr.Labels
						if labels == nil {
							labels = make(map[string]string)
						}
						labels["tls-compliance.telco.openshift.io/host-network"] = "true"
						cr.Labels = labels
					}); err != nil && !apierrors.IsNotFound(err) {
						logger.Error(err, "failed to label hostNetwork CR", "name", crName)
					}
				}
			}
		}
	})
}

// scanAllEndpoints re-checks all existing TLSComplianceReport CRs using a worker pool.
func (r *EndpointReconciler) scanAllEndpoints(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// Phase 1: Discover new pod endpoints
	var podScanErr error
	if err := r.scanPodEndpoints(ctx); err != nil {
		logger.Error(err, "pod endpoint scan failed")
		podScanErr = err
	}

	r.InitialScanDone.Store(true)

	type scanItem struct {
		name       string
		host       string
		port       int
		namespace  string
		status     securityv1alpha1.ComplianceStatus
		checkCount int64
	}

	statusCounts := map[string]float64{
		string(securityv1alpha1.ComplianceStatusCompliant):         0,
		string(securityv1alpha1.ComplianceStatusNonCompliant):      0,
		string(securityv1alpha1.ComplianceStatusWarning):           0,
		string(securityv1alpha1.ComplianceStatusUnreachable):       0,
		string(securityv1alpha1.ComplianceStatusTimeout):           0,
		string(securityv1alpha1.ComplianceStatusClosed):            0,
		string(securityv1alpha1.ComplianceStatusFiltered):          0,
		string(securityv1alpha1.ComplianceStatusNoTLS):             0,
		string(securityv1alpha1.ComplianceStatusPlaintextHTTP):     0,
		string(securityv1alpha1.ComplianceStatusMutualTLSRequired): 0,
		string(securityv1alpha1.ComplianceStatusPending):           0,
		string(securityv1alpha1.ComplianceStatusUnknown):           0,
	}

	var allItems []scanItem
	var crList securityv1alpha1.TLSComplianceReportList
	if err := paginatedList(ctx, r.apiReader(), &crList, func() {
		for i := range crList.Items {
			cr := &crList.Items[i]
			allItems = append(allItems, scanItem{
				name:       cr.Name,
				host:       cr.Spec.Host,
				port:       int(cr.Spec.Port),
				namespace:  cr.Spec.SourceNamespace,
				status:     cr.Status.ComplianceStatus,
				checkCount: cr.Status.CheckCount,
			})
			if _, ok := statusCounts[string(cr.Status.ComplianceStatus)]; ok {
				statusCounts[string(cr.Status.ComplianceStatus)]++
			}
		}
	}); err != nil {
		return fmt.Errorf("failed to list TLSComplianceReports: %w", err)
	}

	workers := r.Workers
	if workers <= 0 {
		workers = 5
	}

	sort.SliceStable(allItems, func(i, j int) bool {
		iPending := allItems[i].status == securityv1alpha1.ComplianceStatusPending ||
			allItems[i].checkCount == 0
		jPending := allItems[j].status == securityv1alpha1.ComplianceStatusPending ||
			allItems[j].checkCount == 0
		return iPending && !jPending
	})

	items := make(chan scanItem, len(allItems))
	for i := range allItems {
		items <- allItems[i]
	}
	close(items)

	var wg sync.WaitGroup
	for range min(workers, len(allItems)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range items {
				select {
				case <-ctx.Done():
					return
				default:
				}
				r.performTLSCheck(ctx, item.name, item.host, item.port, item.namespace, false)
			}
		}()
	}
	wg.Wait()

	r.updateEndpointMetrics(statusCounts)

	logger.Info("scan completed", "endpoints", len(allItems), "workers", workers)
	return podScanErr
}

// updateEndpointMetrics sets the per-status endpoint gauge from pre-computed counts.
func (r *EndpointReconciler) updateEndpointMetrics(statusCounts map[string]float64) {
	for status, count := range statusCounts {
		metrics.EndpointsTotal.WithLabelValues(status).Set(count)
	}
}
