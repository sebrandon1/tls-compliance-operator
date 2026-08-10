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
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/internal/metrics"
)

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
				} else {
					metrics.RecordCleanupCycleCompleted()
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
// in memory to avoid N+1 API calls. All listings use paginated API calls to bound peak memory.
func (r *EndpointReconciler) cleanupOrphanedCRs(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// Pass 1: paginate CRs to discover which source kinds are in use.
	neededKinds := make(map[securityv1alpha1.SourceKind]bool)
	var foundCRs bool
	var crList securityv1alpha1.TLSComplianceReportList
	if err := paginatedList(ctx, r.apiReader(), &crList, func() {
		for i := range crList.Items {
			neededKinds[crList.Items[i].Spec.SourceKind] = true
			foundCRs = true
		}
	}); err != nil {
		return fmt.Errorf("failed to list TLSComplianceReports: %w", err)
	}

	if !foundCRs {
		return nil
	}

	existingSources := make(map[securityv1alpha1.SourceKind]map[string]bool)

	if neededKinds[securityv1alpha1.SourceKindService] {
		var svcList corev1.ServiceList
		svcSet, err := r.collectNamespacedSet(ctx, &svcList, func() int { return len(svcList.Items) }, func(i int) (string, string) {
			return svcList.Items[i].Namespace, svcList.Items[i].Name
		})
		if err != nil {
			logger.Error(err, "failed to list Services for cleanup")
		} else {
			existingSources[securityv1alpha1.SourceKindService] = svcSet
		}
	}

	if neededKinds[securityv1alpha1.SourceKindIngress] {
		var ingList networkingv1.IngressList
		ingSet, err := r.collectNamespacedSet(ctx, &ingList, func() int { return len(ingList.Items) }, func(i int) (string, string) {
			return ingList.Items[i].Namespace, ingList.Items[i].Name
		})
		if err != nil {
			logger.Error(err, "failed to list Ingresses for cleanup")
		} else {
			existingSources[securityv1alpha1.SourceKindIngress] = ingSet
		}
	}

	if neededKinds[securityv1alpha1.SourceKindRoute] && r.RouteAPIAvailable {
		routeSet, err := r.collectUnstructuredSet(ctx, routeGVK)
		if err != nil {
			logger.Error(err, "failed to list Routes for cleanup")
		} else {
			existingSources[securityv1alpha1.SourceKindRoute] = routeSet
		}
	}

	if neededKinds[securityv1alpha1.SourceKindPod] {
		var podList corev1.PodList
		podSet, err := r.collectNamespacedSet(ctx, &podList, func() int { return len(podList.Items) }, func(i int) (string, string) {
			return podList.Items[i].Namespace, podList.Items[i].Name
		})
		if err != nil {
			logger.Error(err, "failed to list Pods for cleanup")
		} else {
			existingSources[securityv1alpha1.SourceKindPod] = podSet
		}
	}

	if neededKinds[securityv1alpha1.SourceKindTarget] {
		var targetList securityv1alpha1.TLSComplianceTargetList
		targetSet, err := r.collectNamespacedSet(ctx, &targetList, func() int { return len(targetList.Items) }, func(i int) (string, string) {
			return "cluster-scoped", targetList.Items[i].Name
		})
		if err != nil {
			logger.Error(err, "failed to list TLSComplianceTargets for cleanup")
		} else {
			existingSources[securityv1alpha1.SourceKindTarget] = targetSet
		}
	}

	if r.GatewayAPIAvailable {
		for _, gvkInfo := range []struct {
			gvk  schema.GroupVersionKind
			kind securityv1alpha1.SourceKind
		}{
			{httpRouteGVK, securityv1alpha1.SourceKindHTTPRoute},
			{tlsRouteGVK, securityv1alpha1.SourceKindTLSRoute},
			{gatewayGVK, securityv1alpha1.SourceKindGateway},
		} {
			gwSet, err := r.collectUnstructuredSet(ctx, gvkInfo.gvk)
			if err != nil {
				logger.V(1).Info("failed to list Gateway API resources for cleanup", "kind", gvkInfo.gvk.Kind)
			} else {
				existingSources[gvkInfo.kind] = gwSet
			}
		}
	}

	// Pass 2: paginate CRs again to check for orphans and TTL expiry.
	cutoff := time.Now().Add(-time.Duration(r.ReportRetentionDays) * 24 * time.Hour)
	var crList2 securityv1alpha1.TLSComplianceReportList
	return paginatedList(ctx, r.apiReader(), &crList2, func() {
		for i := range crList2.Items {
			cr := &crList2.Items[i]

			sourceSet, known := existingSources[cr.Spec.SourceKind]
			if known {
				key := sourceKey(cr.Spec.SourceNamespace, cr.Spec.SourceName)
				if !sourceSet[key] {
					logger.Info("deleting orphaned TLSComplianceReport", "name", cr.Name,
						"sourceKind", cr.Spec.SourceKind, "sourceName", cr.Spec.SourceName)
					if err := r.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
						logger.Error(err, "failed to delete orphaned TLSComplianceReport", "name", cr.Name)
					} else {
						metrics.DeleteEndpointMetrics(cr.Spec.Host, fmt.Sprintf("%d", cr.Spec.Port))
					}
					continue
				}
			}

			if r.ReportRetentionDays > 0 {
				var lastActivity time.Time
				if cr.Status.LastCheckAt != nil {
					lastActivity = cr.Status.LastCheckAt.Time
				} else {
					lastActivity = cr.CreationTimestamp.Time
				}
				if lastActivity.Before(cutoff) {
					logger.Info("deleting expired TLSComplianceReport", "name", cr.Name,
						"lastActivity", lastActivity, "retentionDays", r.ReportRetentionDays)
					if err := r.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
						logger.Error(err, "failed to delete expired TLSComplianceReport", "name", cr.Name)
					} else {
						metrics.RecordReportTTLDeleted()
						metrics.DeleteEndpointMetrics(cr.Spec.Host, fmt.Sprintf("%d", cr.Spec.Port))
					}
				}
			}
		}
	})
}

// collectNamespacedSet paginates a typed list and builds a set of sourceKey(namespace, name) entries.
func (r *EndpointReconciler) collectNamespacedSet(ctx context.Context, list client.ObjectList, itemCount func() int, keyParts func(int) (string, string)) (map[string]bool, error) {
	result := make(map[string]bool)
	err := paginatedList(ctx, r.apiReader(), list, func() {
		for i := range itemCount() {
			ns, name := keyParts(i)
			result[sourceKey(ns, name)] = true
		}
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// collectUnstructuredSet paginates an unstructured list for a given GVK and builds a sourceKey set.
func (r *EndpointReconciler) collectUnstructuredSet(ctx context.Context, gvk schema.GroupVersionKind) (map[string]bool, error) {
	result := make(map[string]bool)
	uList := &unstructured.UnstructuredList{}
	uList.SetGroupVersionKind(gvk)
	err := paginatedList(ctx, r.apiReader(), uList, func() {
		for i := range uList.Items {
			result[sourceKey(uList.Items[i].GetNamespace(), uList.Items[i].GetName())] = true
		}
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
