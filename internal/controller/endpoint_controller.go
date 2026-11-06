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
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"

	"golang.org/x/time/rate"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
	"github.com/sebrandon1/tls-compliance-operator/internal/notify"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
	"github.com/sebrandon1/tls-compliance-operator/pkg/hostvalidation"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlsprofile"
)

// routeGVK is the GroupVersionKind for OpenShift Routes, defined once to avoid repetition.
var routeGVK = schema.GroupVersionKind{
	Group:   "route.openshift.io",
	Version: "v1",
	Kind:    "Route",
}

// Event reasons and actions for Kubernetes events
const (
	EventActionScan                = "Scan"
	EventReasonTLSWarning          = "TLSWarning"
	EventReasonTLSNonCompliant     = "TLSNonCompliant"
	EventReasonComplianceChanged   = "ComplianceChanged"
	EventReasonCertificateExpiring = "CertificateExpiring"
	EventReasonCertificateExpired  = "CertificateExpired"
	EventReasonEndpointDiscovered  = "EndpointDiscovered"
	EventReasonRetryExhausted      = "RetryExhausted"
	EventReasonPQCReady            = "PQCReady"
	EventReasonPQCNotReady         = "PQCNotReady"
	EventReasonRescanSkipped       = "RescanSkipped"
)

var errWorkersBusy = errors.New("TLS check deferred: workers busy")

const workerBusyRequeueDelay = 10 * time.Second

const listPageSize = 500

const nodeAddressCacheTTL = time.Minute

// EndpointReconciler reconciles Services, Ingresses, Routes, Gateway API
// resources, TLSComplianceTargets and rescan requests on TLSComplianceReports.
type EndpointReconciler struct {
	client.Client
	APIReader             client.Reader
	Scheme                *runtime.Scheme
	TLSChecker            tlscheck.Checker
	Recorder              events.EventRecorder
	Notifier              *notify.Notifier
	IncludeNamespaces     map[string]bool
	ExcludeNamespaces     map[string]bool
	CertExpiryDays        int
	RouteAPIAvailable     bool
	GatewayAPIAvailable   bool
	GatewayGVKs           []schema.GroupVersionKind
	ProfileFetcher        *tlsprofile.Fetcher
	Workers               int
	MaxRetries            int
	RetryBackoff          time.Duration
	MaxBackoff            time.Duration
	ScanInterval          time.Duration
	ScanWindowStart       string
	ScanWindowEnd         string
	ScanWindowTimezone    string
	ReportRetentionDays   int
	MaxHistoryEntries     int
	MetricsPerEndpoint    bool
	FIPSEnabled           bool
	NamespaceRateLimiters map[string]*rate.Limiter
	DefaultNamespaceRate  *rate.Limiter
	RunOnce               bool
	RunOnceDone           chan error
	InitialScanDone       atomic.Bool
	ManagerCtx            context.Context
	checkTimeout          time.Duration
	checkSem              chan struct{}
	checkSemOnce          sync.Once
	checkWg               sync.WaitGroup
	inFlight              sync.Map
	nodeAddrMu            sync.RWMutex
	nodeAddrCache         []string
	nodeAddrExpiry        time.Time
	circuitMu             sync.Mutex
	circuits              map[string]circuitState
	// now overrides time.Now for the periodic scan loop; tests only.
	now func() time.Time
}

func (r *EndpointReconciler) apiReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *EndpointReconciler) updateStatusWithRetry(ctx context.Context, name string, mutateFn func(*securityv1alpha1.TLSComplianceReport)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cr securityv1alpha1.TLSComplianceReport
		if err := r.Get(ctx, client.ObjectKey{Name: name}, &cr); err != nil {
			return err
		}
		mutateFn(&cr)
		return r.Status().Update(ctx, &cr)
	})
}

func (r *EndpointReconciler) updateWithRetry(ctx context.Context, name string, mutateFn func(*securityv1alpha1.TLSComplianceReport)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cr securityv1alpha1.TLSComplianceReport
		if err := r.Get(ctx, client.ObjectKey{Name: name}, &cr); err != nil {
			return err
		}
		mutateFn(&cr)
		return r.Update(ctx, &cr)
	})
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch;update
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;tlsroutes;grpcroutes;gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=ingresscontrollers,verbs=get;list;watch
// +kubebuilder:rbac:groups=machineconfiguration.openshift.io,resources=kubeletconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=imagecertificationinfoes,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancereports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancereports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancetargets,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancetargets/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=tlscompliancetargets/status,verbs=get;update;patch

// reconcileObject gets req as obj and passes it to handle. Each watched kind
// has its own controller and reconcile function (see SetupWithManager),
// because a request carries only a namespace and name and cannot tell a
// Service from a same-named Ingress, Route or Gateway API object. Requests
// from namespaces outside the filter are dropped; cluster-scoped kinds have no
// namespace and are never filtered here.
func reconcileObject[T client.Object](
	ctx context.Context,
	r *EndpointReconciler,
	req ctrl.Request,
	kind string,
	obj T,
	handle func(context.Context, T) (ctrl.Result, error),
) (ctrl.Result, error) {
	if req.Namespace != "" && r.isNamespaceFiltered(req.Namespace) {
		return ctrl.Result{}, nil
	}

	start := time.Now()
	metrics.RecordReconcileInFlightInc()
	defer metrics.RecordReconcileInFlightDec()

	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	result, err := handle(ctx, obj)
	metrics.RecordReconcileLatency(kind, time.Since(start).Seconds())
	return result, err
}

func newUnstructured(gvk schema.GroupVersionKind) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	return obj
}

func (r *EndpointReconciler) reconcileService(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return reconcileObject(ctx, r, req, "Service", &corev1.Service{}, r.handleService)
}

func (r *EndpointReconciler) reconcileIngress(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return reconcileObject(ctx, r, req, "Ingress", &networkingv1.Ingress{}, r.handleIngress)
}

func (r *EndpointReconciler) reconcileRoute(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return reconcileObject(ctx, r, req, "Route", newUnstructured(routeGVK), r.handleRoute)
}

// gatewayReconciler returns the reconcile function for one Gateway API kind.
func (r *EndpointReconciler) gatewayReconciler(gvk schema.GroupVersionKind) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		return reconcileObject(ctx, r, req, gvk.Kind, newUnstructured(gvk),
			func(ctx context.Context, obj *unstructured.Unstructured) (ctrl.Result, error) {
				return r.handleGatewayResource(ctx, obj, gvk)
			})
	}
}

func (r *EndpointReconciler) reconcileTarget(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return reconcileObject(ctx, r, req, "TLSComplianceTarget", &securityv1alpha1.TLSComplianceTarget{}, r.handleTarget)
}

func (r *EndpointReconciler) reconcileReport(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return reconcileObject(ctx, r, req, "TLSComplianceReport", &securityv1alpha1.TLSComplianceReport{}, r.handleReport)
}

// handleReport runs a rescan requested with the rescan annotation. Reports
// whose source is outside the namespace filter get a RescanSkipped event.
func (r *EndpointReconciler) handleReport(ctx context.Context, report *securityv1alpha1.TLSComplianceReport) (ctrl.Result, error) {
	if !hasRescanAnnotation(report) {
		return ctrl.Result{}, nil
	}
	if r.isReportFiltered(report.Spec.SourceKind, report.Spec.SourceNamespace) {
		r.skipFilteredRescan(ctx, report)
		return ctrl.Result{}, nil
	}
	return r.handleRescan(ctx, report)
}

func hasRescanAnnotation(obj client.Object) bool {
	_, ok := obj.GetAnnotations()[securityv1alpha1.RescanAnnotation]
	return ok
}

func (r *EndpointReconciler) handleEndpoints(ctx context.Context, endpoints []endpoint.Endpoint, sourceKind securityv1alpha1.SourceKind) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	var firstErr error
	var deferred bool
	for i := range endpoints {
		if err := r.processEndpoint(ctx, &endpoints[i]); err != nil {
			if errors.Is(err, errWorkersBusy) {
				deferred = true
				continue
			}
			logger.Error(err, "failed to process endpoint", "host", endpoints[i].Host, "port", endpoints[i].Port)
			metrics.RecordReconcileError(string(sourceKind), metrics.ErrorTypeProcess)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr != nil {
		metrics.RecordReconcileByResource(string(sourceKind), metrics.ResultError)
		metrics.RecordReconcile(metrics.ResultError)
		return ctrl.Result{}, firstErr
	}
	if deferred {
		return ctrl.Result{RequeueAfter: workerBusyRequeueDelay}, nil
	}
	metrics.RecordReconcileSuccess(string(sourceKind))
	return ctrl.Result{}, nil
}

func (r *EndpointReconciler) handleService(ctx context.Context, svc *corev1.Service) (ctrl.Result, error) {
	if endpoint.ShouldSkipResource(svc.Annotations) {
		log.FromContext(ctx).V(1).Info("skipping service (skip annotation set)", "service", svc.Name, "namespace", svc.Namespace)
		metrics.RecordReconcileSuccess("Service")
		return ctrl.Result{}, nil
	}

	if endpoint.IsHeadlessService(svc) {
		return r.handleHeadlessService(ctx, svc)
	}
	endpoints := endpoint.ExtractFromService(svc)

	if svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		nodeAddrs, err := r.getNodeAddresses(ctx)
		if err != nil {
			log.FromContext(ctx).Error(err, "failed to list node addresses for NodePort scan", "service", svc.Name)
		} else if len(nodeAddrs) > 0 {
			endpoints = append(endpoints, endpoint.ExtractFromNodePortService(svc, nodeAddrs)...)
		}
	}

	endpoints = endpoint.AppendExtraPorts(endpoints, svc.Annotations, svc.Name, svc.Namespace, securityv1alpha1.SourceKindService)
	if len(endpoints) == 0 {
		metrics.RecordReconcileSuccess("Service")
		return ctrl.Result{}, nil
	}
	return r.handleEndpoints(ctx, endpoints, securityv1alpha1.SourceKindService)
}

func (r *EndpointReconciler) getNodeAddresses(ctx context.Context) ([]string, error) {
	r.nodeAddrMu.RLock()
	cached := r.cloneCachedNodeAddresses()
	r.nodeAddrMu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	addrs, err := r.listNodeAddresses(ctx)
	if err != nil {
		return nil, err
	}

	r.nodeAddrMu.Lock()
	defer r.nodeAddrMu.Unlock()
	if cached := r.cloneCachedNodeAddresses(); cached != nil {
		return cached, nil
	}
	if len(addrs) == 0 {
		r.nodeAddrCache = nil
		r.nodeAddrExpiry = time.Time{}
		return addrs, nil
	}
	r.nodeAddrCache = addrs
	r.nodeAddrExpiry = time.Now().Add(nodeAddressCacheTTL)
	return slices.Clone(addrs), nil
}

func (r *EndpointReconciler) cloneCachedNodeAddresses() []string {
	if len(r.nodeAddrCache) > 0 && time.Now().Before(r.nodeAddrExpiry) {
		return slices.Clone(r.nodeAddrCache)
	}
	return nil
}

func (r *EndpointReconciler) listNodeAddresses(ctx context.Context) ([]string, error) {
	var nodeList corev1.NodeList
	if err := r.List(ctx, &nodeList); err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}
	var addrs []string
	seen := make(map[string]bool)
	for i := range nodeList.Items {
		for _, addr := range nodeList.Items[i].Status.Addresses {
			if (addr.Type == corev1.NodeExternalIP || addr.Type == corev1.NodeInternalIP) && !seen[addr.Address] {
				seen[addr.Address] = true
				addrs = append(addrs, addr.Address)
			}
		}
	}
	return addrs, nil
}

func (r *EndpointReconciler) handleHeadlessService(ctx context.Context, svc *corev1.Service) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var epSlices discoveryv1.EndpointSliceList
	if err := r.List(ctx, &epSlices,
		client.InNamespace(svc.Namespace),
		client.MatchingLabels{"kubernetes.io/service-name": svc.Name},
	); err != nil {
		logger.Error(err, "failed to list EndpointSlices for headless service", "service", svc.Name)
		return ctrl.Result{}, err
	}

	var addresses []string
	for i := range epSlices.Items {
		for _, ep := range epSlices.Items[i].Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			addresses = append(addresses, ep.Addresses...)
		}
	}

	endpoints := endpoint.ExtractFromHeadlessService(svc, addresses)
	if len(endpoints) == 0 {
		metrics.RecordReconcileSuccess("Service")
		return ctrl.Result{}, nil
	}
	return r.handleEndpoints(ctx, endpoints, securityv1alpha1.SourceKindService)
}

func (r *EndpointReconciler) handleIngress(ctx context.Context, ing *networkingv1.Ingress) (ctrl.Result, error) {
	if endpoint.ShouldSkipResource(ing.Annotations) {
		log.FromContext(ctx).V(1).Info("skipping ingress (skip annotation set)", "ingress", ing.Name, "namespace", ing.Namespace)
		metrics.RecordReconcileSuccess("Ingress")
		return ctrl.Result{}, nil
	}

	endpoints := endpoint.ExtractFromIngress(ing)
	endpoints = endpoint.AppendExtraPorts(endpoints, ing.Annotations, ing.Name, ing.Namespace, securityv1alpha1.SourceKindIngress)
	return r.handleEndpoints(ctx, endpoints, securityv1alpha1.SourceKindIngress)
}

func (r *EndpointReconciler) handleRoute(ctx context.Context, route *unstructured.Unstructured) (ctrl.Result, error) {
	annotations := route.GetAnnotations()
	if endpoint.ShouldSkipResource(annotations) {
		log.FromContext(ctx).V(1).Info("skipping route (skip annotation set)", "route", route.GetName(), "namespace", route.GetNamespace())
		metrics.RecordReconcileSuccess("Route")
		return ctrl.Result{}, nil
	}

	endpoints := endpoint.ExtractFromRoute(route)
	endpoints = endpoint.AppendExtraPorts(endpoints, annotations, route.GetName(), route.GetNamespace(), securityv1alpha1.SourceKindRoute)
	return r.handleEndpoints(ctx, endpoints, securityv1alpha1.SourceKindRoute)
}

func (r *EndpointReconciler) handleGatewayResource(ctx context.Context, obj *unstructured.Unstructured, gvk schema.GroupVersionKind) (ctrl.Result, error) {
	annotations := obj.GetAnnotations()
	if endpoint.ShouldSkipResource(annotations) {
		log.FromContext(ctx).V(1).Info("skipping gateway resource (skip annotation set)", "kind", gvk.Kind, "name", obj.GetName(), "namespace", obj.GetNamespace())
		metrics.RecordReconcileSuccess(gvk.Kind)
		return ctrl.Result{}, nil
	}

	var endpoints []endpoint.Endpoint
	var sourceKind securityv1alpha1.SourceKind
	switch gvk.Kind {
	case "HTTPRoute":
		endpoints = endpoint.ExtractFromHTTPRoute(obj)
		sourceKind = securityv1alpha1.SourceKindHTTPRoute
	case "TLSRoute":
		endpoints = endpoint.ExtractFromTLSRoute(obj)
		sourceKind = securityv1alpha1.SourceKindTLSRoute
	case "GRPCRoute":
		endpoints = endpoint.ExtractFromGRPCRoute(obj)
		sourceKind = securityv1alpha1.SourceKindGRPCRoute
	case "Gateway":
		endpoints = endpoint.ExtractFromGateway(obj)
		sourceKind = securityv1alpha1.SourceKindGateway
	}
	endpoints = endpoint.AppendExtraPorts(endpoints, annotations, obj.GetName(), obj.GetNamespace(), sourceKind)
	return r.handleEndpoints(ctx, endpoints, sourceKind)
}

func (r *EndpointReconciler) handleTarget(ctx context.Context, target *securityv1alpha1.TLSComplianceTarget) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	ep := endpoint.Endpoint{
		Host:            target.Spec.Host,
		Port:            target.Spec.EffectivePort(),
		SourceKind:      securityv1alpha1.SourceKindTarget,
		SourceNamespace: "cluster-scoped",
		SourceName:      target.Name,
	}

	crName := endpoint.GenerateCRName(&ep)

	// The admission webhook is optional, so re-check here before probing.
	if !hostvalidation.IsSafeHost(ep.Host) {
		logger.Info("skipping Target with internal or reserved host", "target", target.Name, "host", ep.Host)
		r.updateTargetStatus(ctx, target.Name, "", "", fmt.Sprintf("host %q is an internal or reserved address and will not be probed", ep.Host))
		return ctrl.Result{}, nil
	}

	if err := r.processEndpoint(ctx, &ep); err != nil {
		if errors.Is(err, errWorkersBusy) {
			return ctrl.Result{RequeueAfter: workerBusyRequeueDelay}, nil
		}
		logger.Error(err, "failed to process Target endpoint", "host", ep.Host, "port", ep.Port)
		metrics.RecordReconcileError(string(securityv1alpha1.SourceKindTarget), metrics.ErrorTypeProcess)
		metrics.RecordReconcileByResource("TLSComplianceTarget", metrics.ResultError)
		metrics.RecordReconcile(metrics.ResultError)
		r.updateTargetStatus(ctx, target.Name, crName, "", err.Error())
		return ctrl.Result{}, err
	}

	var report securityv1alpha1.TLSComplianceReport
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &report); err == nil {
		if err := r.ensureOwnerReference(ctx, crName, target); err != nil {
			logger.Error(err, "failed to set owner reference", "report", crName, "target", target.Name)
		}
		r.updateTargetStatus(ctx, target.Name, crName, string(report.Status.ComplianceStatus), "")
	}

	metrics.RecordReconcileSuccess("TLSComplianceTarget")
	return ctrl.Result{}, nil
}

// skipFilteredRescan leaves the rescan annotation in place on a report outside
// the namespace filter and says why, since cleanup is about to delete it.
func (r *EndpointReconciler) skipFilteredRescan(ctx context.Context, report *securityv1alpha1.TLSComplianceReport) {
	log.FromContext(ctx).Info("ignoring rescan for report outside the namespace filter",
		"report", report.Name, "sourceNamespace", report.Spec.SourceNamespace)
	if r.Recorder != nil {
		r.Recorder.Eventf(report, nil, corev1.EventTypeWarning, EventReasonRescanSkipped, EventActionScan,
			"Rescan ignored: source namespace %q is outside the operator's namespace filter", report.Spec.SourceNamespace)
	}
}

func (r *EndpointReconciler) handleRescan(ctx context.Context, report *securityv1alpha1.TLSComplianceReport) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("rescan requested", "report", report.Name)

	// Claim before consuming the annotation so a busy report keeps the request.
	release, claimed := r.claimCheck(report.Name)
	if !claimed {
		logger.V(1).Info("rescan deferred, check already in flight", "report", report.Name)
		return ctrl.Result{RequeueAfter: workerBusyRequeueDelay}, nil
	}
	defer release()

	if err := r.updateWithRetry(ctx, report.Name, func(cr *securityv1alpha1.TLSComplianceReport) {
		delete(cr.Annotations, securityv1alpha1.RescanAnnotation)
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("removing rescan annotation: %w", err)
	}

	r.recordCircuitSuccess(report.Name)
	r.performTLSCheck(ctx, report.Name, report.Spec.Host, int(report.Spec.Port), report.Spec.SourceNamespace, false)
	return ctrl.Result{}, nil
}

// ensureOwnerReference adds a TLSComplianceTarget as an owner of the given
// TLSComplianceReport so that deleting the target cascades to its reports.
// Uses updateWithRetry for conflict resilience.
func (r *EndpointReconciler) ensureOwnerReference(ctx context.Context, reportName string, target *securityv1alpha1.TLSComplianceTarget) error {
	return r.updateWithRetry(ctx, reportName, func(cr *securityv1alpha1.TLSComplianceReport) {
		for _, ref := range cr.OwnerReferences {
			if ref.UID == target.UID {
				return
			}
		}
		blockDeletion := true
		cr.OwnerReferences = append(cr.OwnerReferences, metav1.OwnerReference{
			APIVersion:         securityv1alpha1.GroupVersion.String(),
			Kind:               "TLSComplianceTarget",
			Name:               target.Name,
			UID:                target.UID,
			BlockOwnerDeletion: &blockDeletion,
		})
	})
}

func (r *EndpointReconciler) getNamespaceLimiter(namespace string) *rate.Limiter {
	if r.NamespaceRateLimiters != nil {
		if limiter, ok := r.NamespaceRateLimiters[namespace]; ok {
			return limiter
		}
	}
	return r.DefaultNamespaceRate
}

func (r *EndpointReconciler) initCheckSemaphore() {
	r.checkSemOnce.Do(func() {
		workers := r.Workers
		if workers <= 0 {
			workers = 5
		}
		r.checkSem = make(chan struct{}, workers)
	})
}

// SetupWithManager registers one controller per watched kind. Each has its own
// work queue, so objects of different kinds that share a namespace and name
// are reconciled independently. --workers sets MaxConcurrentReconciles for
// each controller; the checkSem worker pool is shared, so it still caps
// async TLS checks across all of them. Route and Gateway API controllers are
// registered only when those APIs are present.
func (r *EndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.initCheckSemaphore()

	newController := func(name string, obj client.Object, opts ...builder.ForOption) *builder.TypedBuilder[reconcile.Request] {
		return ctrl.NewControllerManagedBy(mgr).
			Named("endpoint-"+name).
			For(obj, opts...).
			WithOptions(controller.Options{MaxConcurrentReconciles: r.Workers})
	}

	enqueueOwnerService := func(_ context.Context, obj client.Object) []ctrl.Request {
		svcName := obj.GetLabels()["kubernetes.io/service-name"]
		if svcName == "" {
			return nil
		}
		return []ctrl.Request{{NamespacedName: client.ObjectKey{
			Namespace: obj.GetNamespace(),
			Name:      svcName,
		}}}
	}

	type kindController struct {
		builder   *builder.TypedBuilder[reconcile.Request]
		reconcile reconcile.Func
	}
	controllers := []kindController{
		{
			newController("service", &corev1.Service{}).
				Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(enqueueOwnerService)),
			r.reconcileService,
		},
		{newController("ingress", &networkingv1.Ingress{}), r.reconcileIngress},
		{newController("target", &securityv1alpha1.TLSComplianceTarget{}), r.reconcileTarget},
		{
			// Only rescan requests are queued. Delete events bypass the queue:
			// they only drop the report's per-endpoint metric series, so
			// reports removed by kubectl, owner-reference cascades or a rescan
			// do not leak them.
			newController("report", &securityv1alpha1.TLSComplianceReport{},
				builder.WithPredicates(predicate.AnnotationChangedPredicate{}, predicate.NewPredicateFuncs(hasRescanAnnotation))).
				Watches(&securityv1alpha1.TLSComplianceReport{}, handler.Funcs{DeleteFunc: r.handleReportDeleted}),
			r.reconcileReport,
		},
	}
	if r.RouteAPIAvailable {
		controllers = append(controllers, kindController{newController("route", newUnstructured(routeGVK)), r.reconcileRoute})
	}
	for _, gvk := range r.GatewayGVKs {
		controllers = append(controllers, kindController{newController(strings.ToLower(gvk.Kind), newUnstructured(gvk)), r.gatewayReconciler(gvk)})
	}

	for _, c := range controllers {
		if err := c.builder.Complete(c.reconcile); err != nil {
			return err
		}
	}
	return nil
}

// handleReportDeleted drops the per-endpoint metric series belonging to a
// deleted report. Deletion events reach this handler regardless of who deleted
// the object, including the cleanup loop. The handler never reports an error:
// a failed metric delete must not retry or block deletion.
func (r *EndpointReconciler) handleReportDeleted(
	ctx context.Context,
	e event.DeleteEvent,
	_ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
	report, ok := e.Object.(*securityv1alpha1.TLSComplianceReport)
	if !ok || report.Spec.Host == "" || report.Spec.Port <= 0 {
		return
	}
	r.releaseEndpointMetrics(ctx, report.Name, report.Spec.Host, report.Spec.Port)
}

// releaseEndpointMetrics deletes the per-endpoint metrics for host:port once
// the named report is gone. The metrics are labeled by host and port only, so
// they stay while another report (for example, a Target and an Ingress for
// the same address) still covers that endpoint.
func (r *EndpointReconciler) releaseEndpointMetrics(ctx context.Context, deletedName, host string, port int32) {
	var reports securityv1alpha1.TLSComplianceReportList
	if err := r.List(ctx, &reports, client.UnsafeDisableDeepCopy); err != nil {
		log.FromContext(ctx).Error(err, "listing reports before deleting endpoint metrics", "host", host, "port", port)
		return
	}
	for i := range reports.Items {
		cr := &reports.Items[i]
		if cr.Name != deletedName && cr.Spec.Host == host && cr.Spec.Port == port {
			return
		}
	}
	metrics.DeleteEndpointMetrics(host, fmt.Sprintf("%d", port))
}

func determineComplianceStatus(result *tlscheck.TLSCheckResult) securityv1alpha1.ComplianceStatus {
	hasModern := result.SupportsTLS12 || result.SupportsTLS13
	hasLegacy := result.SupportsSSL30 || result.SupportsTLS10 || result.SupportsTLS11

	if hasModern && hasLegacy {
		return securityv1alpha1.ComplianceStatusWarning
	}
	if hasModern {
		return securityv1alpha1.ComplianceStatusCompliant
	}
	if hasLegacy {
		return securityv1alpha1.ComplianceStatusNonCompliant
	}
	return securityv1alpha1.ComplianceStatusUnknown
}

// isQuantumReady returns true if any negotiated curve uses a hybrid ML-KEM
// key exchange (e.g. X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).
func isQuantumReady(curves map[string]string) bool {
	for _, curve := range curves {
		if strings.Contains(curve, "MLKEM") {
			return true
		}
	}
	return false
}

// determinePQCReadiness classifies the post-quantum cryptography readiness of
// an endpoint based on its TLS version support and negotiated key exchange curves.
func determinePQCReadiness(result *tlscheck.TLSCheckResult) securityv1alpha1.PQCReadiness {
	if !result.SupportsTLS10 && !result.SupportsTLS11 && !result.SupportsTLS12 && !result.SupportsTLS13 {
		return securityv1alpha1.PQCReadinessNoPQC
	}
	if !result.SupportsTLS13 {
		return securityv1alpha1.PQCReadinessLegacyTLS
	}
	if result.MLKEMSupported || isQuantumReady(result.NegotiatedCurves) {
		return securityv1alpha1.PQCReadinessPQCReady
	}
	return securityv1alpha1.PQCReadinessTLS13Capable
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

// isReportFiltered reports whether an existing TLSComplianceReport falls
// outside the current namespace filter. TLSComplianceTarget reports are
// cluster-scoped and have no source namespace, so they are never filtered.
func (r *EndpointReconciler) isReportFiltered(kind securityv1alpha1.SourceKind, sourceNamespace string) bool {
	if kind == securityv1alpha1.SourceKindTarget {
		return false
	}
	return r.isNamespaceFiltered(sourceNamespace)
}

// failureReasonToComplianceStatus maps a TLS check failure reason to the
// corresponding compliance status. Used by both performTLSCheck and updateRetryStatus.
func failureReasonToComplianceStatus(reason tlscheck.FailureReason) securityv1alpha1.ComplianceStatus {
	switch reason {
	case tlscheck.FailureReasonNoTLS:
		return securityv1alpha1.ComplianceStatusNoTLS
	case tlscheck.FailureReasonPlaintextHTTP:
		return securityv1alpha1.ComplianceStatusPlaintextHTTP
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

// hostPort formats a host and port for display, using net.JoinHostPort to
// correctly bracket IPv6 addresses (e.g. "[::1]:443").
func hostPort(host string, port int32) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// ReportsInFilter returns the reports that the namespace filter keeps.
func (r *EndpointReconciler) ReportsInFilter(reports []securityv1alpha1.TLSComplianceReport) []securityv1alpha1.TLSComplianceReport {
	kept := make([]securityv1alpha1.TLSComplianceReport, 0, len(reports))
	for i := range reports {
		if !r.isReportFiltered(reports[i].Spec.SourceKind, reports[i].Spec.SourceNamespace) {
			kept = append(kept, reports[i])
		}
	}
	return kept
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
