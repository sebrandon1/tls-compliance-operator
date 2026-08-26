package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
)

func TestBuildDigestLabel(t *testing.T) {
	tests := []struct {
		name    string
		imageID string
		want    string
	}{
		{
			name:    "empty imageID",
			imageID: "",
			want:    "",
		},
		{
			name:    "bare sha256 digest",
			imageID: "sha256:abcdef1234567890abcdef1234567890abcdef12",
			want:    "sha256-abcdef1234567890",
		},
		{
			name:    "full imageID with registry and repo",
			imageID: "registry.example.com/repo/image@sha256:fedcba0987654321fedcba0987654321",
			want:    "sha256-fedcba0987654321",
		},
		{
			name:    "no sha256 prefix at all",
			imageID: "registry.example.com/repo/image:latest",
			want:    "",
		},
		{
			name:    "digest shorter than 16 chars uses full hex",
			imageID: "sha256:abc123",
			want:    "sha256-abc123",
		},
		{
			name:    "exactly 16 hex chars",
			imageID: "sha256:1234567890abcdef",
			want:    "sha256-1234567890abcdef",
		},
		{
			name:    "docker-style imageID with @sha256",
			imageID: "docker.io/library/nginx@sha256:deadbeef12345678deadbeef12345678deadbeef",
			want:    "sha256-deadbeef12345678",
		},
		{
			name:    "sha256 prefix with empty digest",
			imageID: "sha256:",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDigestLabel(tt.imageID)
			if got != tt.want {
				t.Errorf("buildDigestLabel(%q) = %q, want %q", tt.imageID, got, tt.want)
			}
		})
	}
}

func TestNestedStringField(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"certificationStatus": "Certified",
			"pyxisData": map[string]interface{}{
				"healthIndex": "A",
			},
		},
	}

	t.Run("top-level nested field exists", func(t *testing.T) {
		if got := nestedStringField(obj, "status", "certificationStatus"); got != "Certified" {
			t.Errorf("nestedStringField = %q, want Certified", got)
		}
	})

	t.Run("deeply nested field exists", func(t *testing.T) {
		if got := nestedStringField(obj, "status", "pyxisData", "healthIndex"); got != "A" {
			t.Errorf("nestedStringField = %q, want A", got)
		}
	})

	t.Run("field missing at leaf", func(t *testing.T) {
		if got := nestedStringField(obj, "status", "missing"); got != "" {
			t.Errorf("nestedStringField = %q, want empty", got)
		}
	})

	t.Run("intermediate map missing", func(t *testing.T) {
		if got := nestedStringField(obj, "nonexistent", "field"); got != "" {
			t.Errorf("nestedStringField = %q, want empty", got)
		}
	})

	t.Run("intermediate value not a map", func(t *testing.T) {
		if got := nestedStringField(obj, "status", "certificationStatus", "subfield"); got != "" {
			t.Errorf("nestedStringField = %q, want empty", got)
		}
	})
}

func TestNestedInt64Field(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"daysUntilEol": int64(180),
			"pyxisData": map[string]interface{}{
				"vulnerabilities": map[string]interface{}{
					"critical": float64(3),
				},
				"countAsInt": int(7),
			},
		},
	}

	t.Run("int64 value", func(t *testing.T) {
		got, found := nestedInt64Field(obj, "status", "daysUntilEol")
		if !found || got != 180 {
			t.Errorf("nestedInt64Field = (%d, %v), want (180, true)", got, found)
		}
	})

	t.Run("float64 coerced to int64", func(t *testing.T) {
		got, found := nestedInt64Field(obj, "status", "pyxisData", "vulnerabilities", "critical")
		if !found || got != 3 {
			t.Errorf("nestedInt64Field = (%d, %v), want (3, true)", got, found)
		}
	})

	t.Run("int coerced to int64", func(t *testing.T) {
		got, found := nestedInt64Field(obj, "status", "pyxisData", "countAsInt")
		if !found || got != 7 {
			t.Errorf("nestedInt64Field = (%d, %v), want (7, true)", got, found)
		}
	})

	t.Run("field missing at leaf", func(t *testing.T) {
		got, found := nestedInt64Field(obj, "status", "missing")
		if found || got != 0 {
			t.Errorf("nestedInt64Field = (%d, %v), want (0, false)", got, found)
		}
	})

	t.Run("intermediate map missing", func(t *testing.T) {
		got, found := nestedInt64Field(obj, "nonexistent", "field")
		if found || got != 0 {
			t.Errorf("nestedInt64Field = (%d, %v), want (0, false)", got, found)
		}
	})

	t.Run("value found but wrong type", func(t *testing.T) {
		wrongType := map[string]interface{}{
			"val": "not-a-number",
		}
		got, found := nestedInt64Field(wrongType, "val")
		if found || got != 0 {
			t.Errorf("nestedInt64Field (wrong type) = (%d, %v), want (0, false)", got, found)
		}
	})
}

const (
	testEnrichImageID   = "registry.example.com/repo@sha256:abcdef1234567890abcdef1234567890abcdef00"
	testEnrichDigestLbl = "sha256-abcdef1234567890"
)

func newEnrichReconciler(t *testing.T, objs []client.Object, funcs *interceptor.Funcs) *EndpointReconciler {
	t.Helper()
	scheme := newTestScheme()
	b := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&securityv1alpha1.TLSComplianceReport{})
	if funcs != nil {
		b = b.WithInterceptorFuncs(*funcs)
	}
	return &EndpointReconciler{Client: b.Build(), Scheme: scheme}
}

func newTestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ImageID: testEnrichImageID},
			},
		},
	}
}

func newTestTLSReport() *securityv1alpha1.TLSComplianceReport {
	return &securityv1alpha1.TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "test-report"},
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "example.com",
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindPod,
			SourceNamespace: "default",
			SourceName:      "test-pod",
		},
	}
}

func newTestICIUnstructured(status map[string]interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": iciGroup + "/" + iciVersion,
			"kind":       iciKind,
			"metadata": map[string]interface{}{
				"name": "test-ici",
				"labels": map[string]interface{}{
					iciDigestLabel: testEnrichDigestLbl,
				},
			},
			"status": status,
		},
	}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   iciGroup,
		Version: iciVersion,
		Kind:    iciKind,
	})
	return obj
}

func interceptListWithICI(items []unstructured.Unstructured) *interceptor.Funcs {
	return &interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if uList, ok := list.(*unstructured.UnstructuredList); ok && uList.GetKind() == iciListKind {
				uList.Items = items
				return nil
			}
			return cl.List(ctx, list, opts...)
		},
	}
}

func TestEnrichWithImageCertInfo_SkipsContainersWithEmptyImageID(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ImageID: ""},
			},
		},
	}
	cr := newTestTLSReport()
	r := newEnrichReconciler(t, []client.Object{pod, cr}, nil)
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.ImageCertificationInfo != nil {
		t.Errorf("expected nil ImageCertificationInfo when ImageID is empty")
	}
}

func TestEnrichWithImageCertInfo_SkipsContainersWithNoSHA256(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ImageID: "docker.io/library/nginx:latest"},
			},
		},
	}
	cr := newTestTLSReport()
	r := newEnrichReconciler(t, []client.Object{pod, cr}, nil)
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.ImageCertificationInfo != nil {
		t.Errorf("expected nil ImageCertificationInfo when ImageID has no sha256")
	}
}

func TestEnrichWithImageCertInfo_ListErrorNonMatch(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()
	r := newEnrichReconciler(t, []client.Object{pod, cr}, &interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if uList, ok := list.(*unstructured.UnstructuredList); ok && uList.GetKind() == iciListKind {
				return fmt.Errorf("injected list error")
			}
			return cl.List(ctx, list, opts...)
		},
	})
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.ImageCertificationInfo != nil {
		t.Errorf("expected nil ImageCertificationInfo after List error")
	}
}

func TestEnrichWithImageCertInfo_StatusUpdateError(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()
	ici := newTestICIUnstructured(map[string]interface{}{
		"certificationStatus": "Certified",
	})
	r := newEnrichReconciler(t, []client.Object{pod, cr}, &interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if uList, ok := list.(*unstructured.UnstructuredList); ok && uList.GetKind() == iciListKind {
				uList.Items = []unstructured.Unstructured{*ici}
				return nil
			}
			return cl.List(ctx, list, opts...)
		},
		SubResourceUpdate: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			return fmt.Errorf("injected status update error")
		},
	})
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")
}

func TestEnrichWithImageCertInfo_NonPodSourceKind(t *testing.T) {
	r := newEnrichReconciler(t, nil, nil)
	ep := &endpoint.Endpoint{SourceKind: securityv1alpha1.SourceKindService}
	r.enrichWithImageCertInfo(context.Background(), ep, "any-cr")
}

func TestEnrichWithImageCertInfo_PodNotFound(t *testing.T) {
	cr := newTestTLSReport()
	r := newEnrichReconciler(t, []client.Object{cr}, nil)
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "nonexistent-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.ImageCertificationInfo != nil {
		t.Errorf("expected nil ImageCertificationInfo when pod not found, got %v", got.Status.ImageCertificationInfo)
	}
}

func TestEnrichWithImageCertInfo_ICICRDNotInstalled(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()

	noMatchErr := &apimeta.NoKindMatchError{
		GroupKind: schema.GroupKind{Group: iciGroup, Kind: iciKind},
	}
	r := newEnrichReconciler(t, []client.Object{pod, cr}, &interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if uList, ok := list.(*unstructured.UnstructuredList); ok && uList.GetKind() == iciListKind {
				return noMatchErr
			}
			return cl.List(ctx, list, opts...)
		},
	})
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.ImageCertificationInfo != nil {
		t.Errorf("expected nil ImageCertificationInfo when ICI CRD not installed")
	}
}

func TestEnrichWithImageCertInfo_NoMatchingICICR(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()
	r := newEnrichReconciler(t, []client.Object{pod, cr}, interceptListWithICI(nil))
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.ImageCertificationInfo != nil {
		t.Errorf("expected nil ImageCertificationInfo when no ICI CR matches")
	}
}

func TestEnrichWithImageCertInfo_ICICRFoundFullyPopulated(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()
	ici := newTestICIUnstructured(map[string]interface{}{
		"certificationStatus": "Certified",
		"registryType":        "RedHat",
		"pyxisData": map[string]interface{}{
			"healthIndex": "A",
			"vulnerabilities": map[string]interface{}{
				"critical": float64(2),
			},
		},
		"daysUntilEol": float64(90),
	})
	r := newEnrichReconciler(t, []client.Object{pod, cr}, interceptListWithICI([]unstructured.Unstructured{*ici}))
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Status.ImageCertificationInfo) != 1 {
		t.Fatalf("expected 1 ImageCertificationInfo entry, got %d", len(got.Status.ImageCertificationInfo))
	}
	entry := got.Status.ImageCertificationInfo[0]
	if entry.ContainerName != "app" {
		t.Errorf("ContainerName = %q, want app", entry.ContainerName)
	}
	if entry.ICIName != "test-ici" {
		t.Errorf("ICIName = %q, want test-ici", entry.ICIName)
	}
	if entry.CertificationStatus != "Certified" {
		t.Errorf("CertificationStatus = %q, want Certified", entry.CertificationStatus)
	}
	if entry.RegistryType != "RedHat" {
		t.Errorf("RegistryType = %q, want RedHat", entry.RegistryType)
	}
	if entry.HealthIndex != "A" {
		t.Errorf("HealthIndex = %q, want A", entry.HealthIndex)
	}
	if entry.CriticalCVECount == nil || *entry.CriticalCVECount != 2 {
		t.Errorf("CriticalCVECount = %v, want 2", entry.CriticalCVECount)
	}
	if entry.DaysUntilEOL == nil || *entry.DaysUntilEOL != 90 {
		t.Errorf("DaysUntilEOL = %v, want 90", entry.DaysUntilEOL)
	}
}

func TestEnrichWithImageCertInfoByCRName_CRNotFound(t *testing.T) {
	r := newEnrichReconciler(t, nil, nil)
	r.enrichWithImageCertInfoByCRName(context.Background(), "nonexistent-cr")
}

func TestEnrichWithImageCertInfoByCRName_PodSourceDelegates(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()
	ici := newTestICIUnstructured(map[string]interface{}{
		"certificationStatus": "Certified",
	})
	r := newEnrichReconciler(t, []client.Object{pod, cr}, interceptListWithICI([]unstructured.Unstructured{*ici}))

	r.enrichWithImageCertInfoByCRName(context.Background(), "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Status.ImageCertificationInfo) != 1 {
		t.Fatalf("expected 1 ImageCertificationInfo entry, got %d", len(got.Status.ImageCertificationInfo))
	}
	if got.Status.ImageCertificationInfo[0].CertificationStatus != "Certified" {
		t.Errorf("CertificationStatus = %q, want Certified", got.Status.ImageCertificationInfo[0].CertificationStatus)
	}
}

func TestEnrichWithImageCertInfo_ICICRFoundNoPyxisData(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()
	ici := newTestICIUnstructured(map[string]interface{}{
		"certificationStatus": "NotCertified",
	})
	r := newEnrichReconciler(t, []client.Object{pod, cr}, interceptListWithICI([]unstructured.Unstructured{*ici}))
	ep := &endpoint.Endpoint{
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "test-pod",
	}
	r.enrichWithImageCertInfo(context.Background(), ep, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Status.ImageCertificationInfo) != 1 {
		t.Fatalf("expected 1 ImageCertificationInfo entry, got %d", len(got.Status.ImageCertificationInfo))
	}
	entry := got.Status.ImageCertificationInfo[0]
	if entry.CertificationStatus != "NotCertified" {
		t.Errorf("CertificationStatus = %q, want NotCertified", entry.CertificationStatus)
	}
	if entry.HealthIndex != "" {
		t.Errorf("HealthIndex = %q, want empty when pyxisData absent", entry.HealthIndex)
	}
	if entry.CriticalCVECount != nil {
		t.Errorf("CriticalCVECount = %v, want nil when pyxisData absent", entry.CriticalCVECount)
	}
	if entry.DaysUntilEOL != nil {
		t.Errorf("DaysUntilEOL = %v, want nil when pyxisData absent", entry.DaysUntilEOL)
	}
}

func newTestICIWithMeta(extraLabels, annotations map[string]string, status map[string]interface{}) *unstructured.Unstructured {
	labels := map[string]interface{}{
		iciDigestLabel: testEnrichDigestLbl,
	}
	for k, v := range extraLabels {
		labels[k] = v
	}
	meta := map[string]interface{}{
		"name":   "test-ici",
		"labels": labels,
	}
	if len(annotations) > 0 {
		annots := make(map[string]interface{}, len(annotations))
		for k, v := range annotations {
			annots[k] = v
		}
		meta["annotations"] = annots
	}
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": iciGroup + "/" + iciVersion,
			"kind":       iciKind,
			"metadata":   meta,
			"status":     status,
		},
	}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: iciGroup, Version: iciVersion, Kind: iciKind})
	return obj
}

func TestEnrichExpandedFields(t *testing.T) {
	pod := newTestPod()
	cr := newTestTLSReport()

	ici := newTestICIWithMeta(
		map[string]string{iciVersionLabel: "v0.2.20"},
		map[string]string{iciCVEsAnnotation: "CVE-2024-1234,CVE-2024-5678"},
		map[string]interface{}{
			"certificationStatus": "Certified",
			"registryType":        "RedHat",
			"imageAge":            "45 days",
			"lastPyxisCheckAt":    "2026-08-26T12:00:00Z",
			"pyxisData": map[string]interface{}{
				"healthIndex":        "A",
				"publisher":          "Red Hat, Inc.",
				"releaseCategory":    "Generally Available",
				"autoRebuildEnabled": true,
				"vulnerabilities": map[string]interface{}{
					"critical":  float64(0),
					"important": float64(2),
					"moderate":  float64(5),
					"low":       float64(15),
				},
			},
			"daysUntilEol": int64(120),
		})

	r := newEnrichReconciler(t, []client.Object{pod, cr}, interceptListWithICI([]unstructured.Unstructured{*ici}))
	r.enrichWithImageCertInfo(context.Background(), &endpoint.Endpoint{
		SourceKind: securityv1alpha1.SourceKindPod, SourceNamespace: "default", SourceName: "test-pod",
	}, "test-report")

	var got securityv1alpha1.TLSComplianceReport
	if err := r.Get(context.Background(), client.ObjectKey{Name: "test-report"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Status.ImageCertificationInfo) == 0 {
		t.Fatal("imageCertificationInfo is empty")
	}
	info := got.Status.ImageCertificationInfo[0]

	if info.ICIOperatorVersion != "v0.2.20" {
		t.Errorf("ICIOperatorVersion = %q, want v0.2.20", info.ICIOperatorVersion)
	}
	if info.Publisher != "Red Hat, Inc." {
		t.Errorf("Publisher = %q, want Red Hat, Inc.", info.Publisher)
	}
	if info.ReleaseCategory != "Generally Available" {
		t.Errorf("ReleaseCategory = %q, want Generally Available", info.ReleaseCategory)
	}
	if info.ImageAge != "45 days" {
		t.Errorf("ImageAge = %q, want 45 days", info.ImageAge)
	}
	if info.LastCheckedAt != "2026-08-26T12:00:00Z" {
		t.Errorf("LastCheckedAt = %q, want 2026-08-26T12:00:00Z", info.LastCheckedAt)
	}
	if info.AutoRebuildEnabled == nil || !*info.AutoRebuildEnabled {
		t.Errorf("AutoRebuildEnabled = %v, want true", info.AutoRebuildEnabled)
	}
	if info.ImportantCVECount == nil || *info.ImportantCVECount != 2 {
		t.Errorf("ImportantCVECount = %v, want 2", info.ImportantCVECount)
	}
	if info.ModerateCVECount == nil || *info.ModerateCVECount != 5 {
		t.Errorf("ModerateCVECount = %v, want 5", info.ModerateCVECount)
	}
	if info.LowCVECount == nil || *info.LowCVECount != 15 {
		t.Errorf("LowCVECount = %v, want 15", info.LowCVECount)
	}
	if len(info.CVEIDs) != 2 || !strings.Contains(info.CVEIDs[0], "CVE-2024") {
		t.Errorf("CVEIDs = %v, want [CVE-2024-1234 CVE-2024-5678]", info.CVEIDs)
	}
}
