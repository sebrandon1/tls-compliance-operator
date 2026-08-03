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

package endpoint

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestExtractFromService_HTTPSPort(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443},
			},
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.Host != "my-service.default" {
		t.Errorf("host = %q, want my-service.default", ep.Host)
	}
	if ep.Port != 443 {
		t.Errorf("port = %d, want 443", ep.Port)
	}
	if ep.SourceKind != securityv1alpha1.SourceKindService {
		t.Errorf("sourceKind = %q, want Service", ep.SourceKind)
	}
	if ep.SourceNamespace != "default" {
		t.Errorf("sourceNamespace = %q, want default", ep.SourceNamespace)
	}
	if ep.SourceName != "my-service" {
		t.Errorf("sourceName = %q, want my-service", ep.SourceName)
	}
}

func TestExtractFromService_Port8443(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-server",
			Namespace: "kube-system",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "api", Port: 8443},
			},
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	if endpoints[0].Port != 8443 {
		t.Errorf("port = %d, want 8443", endpoints[0].Port)
	}
}

func TestExtractFromService_HTTPSNamedPort(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "https-metrics", Port: 9443},
			},
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
}

func TestExtractFromService_NonTLSPort(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
				{Name: "grpc", Port: 9090},
			},
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints for non-TLS service, got %d", len(endpoints))
	}
}

func TestExtractFromService_MultiplePorts(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
				{Name: "https", Port: 443},
				{Name: "grpc", Port: 9090},
				{Name: "https-metrics", Port: 8443},
			},
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 TLS endpoints, got %d", len(endpoints))
	}
}

func TestExtractFromService_ExternalName(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-api",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "api.vendor.example.com",
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.Host != "api.vendor.example.com" {
		t.Errorf("host = %q, want api.vendor.example.com", ep.Host)
	}
	if ep.Port != 443 {
		t.Errorf("port = %d, want 443 (default for ExternalName without ports)", ep.Port)
	}
	if ep.SourceKind != securityv1alpha1.SourceKindService {
		t.Errorf("sourceKind = %q, want Service", ep.SourceKind)
	}
	if ep.SourceName != "external-api" {
		t.Errorf("sourceName = %q, want external-api", ep.SourceName)
	}
}

func TestExtractFromService_ExternalNameWithPorts(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-db",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "db.vendor.example.com",
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 8443},
				{Name: "http", Port: 80},
			},
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 TLS endpoint, got %d", len(endpoints))
	}
	if endpoints[0].Host != "db.vendor.example.com" {
		t.Errorf("host = %q, want db.vendor.example.com", endpoints[0].Host)
	}
	if endpoints[0].Port != 8443 {
		t.Errorf("port = %d, want 8443", endpoints[0].Port)
	}
}

func TestExtractFromService_ExternalNameEmpty(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "broken-external",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "",
		},
	}

	endpoints := ExtractFromService(svc)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints for empty ExternalName, got %d", len(endpoints))
	}
}

func TestExtractFromIngress(t *testing.T) {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{
					Hosts: []string{"app.example.com", "api.example.com"},
				},
			},
		},
	}

	endpoints := ExtractFromIngress(ing)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}

	if endpoints[0].Host != "app.example.com" {
		t.Errorf("host = %q, want app.example.com", endpoints[0].Host)
	}
	if endpoints[0].Port != 443 {
		t.Errorf("port = %d, want 443", endpoints[0].Port)
	}
	if endpoints[0].SourceKind != securityv1alpha1.SourceKindIngress {
		t.Errorf("sourceKind = %q, want Ingress", endpoints[0].SourceKind)
	}
}

func TestExtractFromIngress_NoTLS(t *testing.T) {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{},
	}

	endpoints := ExtractFromIngress(ing)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints for non-TLS ingress, got %d", len(endpoints))
	}
}

func TestExtractFromRoute(t *testing.T) {
	route := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "route.openshift.io/v1",
			"kind":       "Route",
			"metadata": map[string]interface{}{
				"name":      "my-route",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"host": "app.example.com",
				"tls": map[string]interface{}{
					"termination": "edge",
				},
			},
		},
	}

	endpoints := ExtractFromRoute(route)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.Host != "app.example.com" {
		t.Errorf("host = %q, want app.example.com", ep.Host)
	}
	if ep.Port != 443 {
		t.Errorf("port = %d, want 443", ep.Port)
	}
	if ep.SourceKind != securityv1alpha1.SourceKindRoute {
		t.Errorf("sourceKind = %q, want Route", ep.SourceKind)
	}
}

func TestExtractFromRoute_NoTLS(t *testing.T) {
	route := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "route.openshift.io/v1",
			"kind":       "Route",
			"metadata": map[string]interface{}{
				"name":      "my-route",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"host": "app.example.com",
			},
		},
	}

	endpoints := ExtractFromRoute(route)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints for non-TLS route, got %d", len(endpoints))
	}
}

func TestGenerateCRName(t *testing.T) {
	ep := Endpoint{
		Host:            "my-service.default",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "my-service",
	}

	name := GenerateCRName(&ep)

	// Should not exceed 63 characters
	if len(name) > MaxCRNameLength {
		t.Errorf("name length %d exceeds max %d: %s", len(name), MaxCRNameLength, name)
	}

	// Should be lowercase
	if name != strings.ToLower(name) {
		t.Errorf("name should be lowercase: %s", name)
	}

	// Should contain port
	if !strings.Contains(name, "443") {
		t.Errorf("name should contain port 443: %s", name)
	}

	// Should be deterministic
	name2 := GenerateCRName(&ep)
	if name != name2 {
		t.Errorf("GenerateCRName is not deterministic: %s != %s", name, name2)
	}
}

func TestGenerateCRName_Uniqueness(t *testing.T) {
	ep1 := Endpoint{
		Host:            "service.default",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "service-a",
	}
	ep2 := Endpoint{
		Host:            "service.default",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "default",
		SourceName:      "service-b",
	}

	name1 := GenerateCRName(&ep1)
	name2 := GenerateCRName(&ep2)

	if name1 == name2 {
		t.Errorf("different endpoints should produce different names: %s", name1)
	}
}

func TestGenerateCRName_LongHost(t *testing.T) {
	ep := Endpoint{
		Host:            "very-long-service-name-that-exceeds-normal-limits.very-long-namespace",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindService,
		SourceNamespace: "very-long-namespace",
		SourceName:      "very-long-service-name-that-exceeds-normal-limits",
	}

	name := GenerateCRName(&ep)
	if len(name) > MaxCRNameLength {
		t.Errorf("name length %d exceeds max %d: %s", len(name), MaxCRNameLength, name)
	}
}

func TestIsTLSPort(t *testing.T) {
	tests := []struct {
		name string
		port corev1.ServicePort
		want bool
	}{
		{"port 443", corev1.ServicePort{Port: 443}, true},
		{"port 8443", corev1.ServicePort{Port: 8443}, true},
		{"port 9443 (webhooks)", corev1.ServicePort{Port: 9443}, true},
		{"port 2379 (etcd)", corev1.ServicePort{Port: 2379}, true},
		{"port 5671 (AMQP TLS)", corev1.ServicePort{Port: 5671}, true},
		{"port 6380 (Redis TLS)", corev1.ServicePort{Port: 6380}, true},
		{"port 9200 (Elasticsearch)", corev1.ServicePort{Port: 9200}, true},
		{"port 2380 (etcd peer)", corev1.ServicePort{Port: 2380}, true},
		{"port 6443 (kube-apiserver)", corev1.ServicePort{Port: 6443}, true},
		{"port 10250 (kubelet)", corev1.ServicePort{Port: 10250}, true},
		{"port 10257 (kube-controller-manager)", corev1.ServicePort{Port: 10257}, true},
		{"port 10259 (kube-scheduler)", corev1.ServicePort{Port: 10259}, true},
		{"port 9091 (Prometheus)", corev1.ServicePort{Port: 9091}, true},
		{"port 9092 (Thanos)", corev1.ServicePort{Port: 9092}, true},
		{"port 9100 (node-exporter)", corev1.ServicePort{Port: 9100}, true},
		{"named https", corev1.ServicePort{Name: "https", Port: 9090}, true},
		{"named https-metrics", corev1.ServicePort{Name: "https-metrics", Port: 7777}, true},
		{"port 80", corev1.ServicePort{Port: 80}, false},
		{"named http", corev1.ServicePort{Name: "http", Port: 80}, false},
		{"named grpc", corev1.ServicePort{Name: "grpc", Port: 9090}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTLSPort(&tt.port)
			if got != tt.want {
				t.Errorf("isTLSPort(%v) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestIsTLSContainerPort(t *testing.T) {
	tests := []struct {
		name string
		port corev1.ContainerPort
		want bool
	}{
		{"port 443", corev1.ContainerPort{ContainerPort: 443}, true},
		{"port 8443", corev1.ContainerPort{ContainerPort: 8443}, true},
		{"port 9443 (webhooks)", corev1.ContainerPort{ContainerPort: 9443}, true},
		{"port 2379 (etcd)", corev1.ContainerPort{ContainerPort: 2379}, true},
		{"port 5671 (AMQP TLS)", corev1.ContainerPort{ContainerPort: 5671}, true},
		{"port 6380 (Redis TLS)", corev1.ContainerPort{ContainerPort: 6380}, true},
		{"port 9200 (Elasticsearch)", corev1.ContainerPort{ContainerPort: 9200}, true},
		{"port 2380 (etcd peer)", corev1.ContainerPort{ContainerPort: 2380}, true},
		{"port 6443 (kube-apiserver)", corev1.ContainerPort{ContainerPort: 6443}, true},
		{"port 10250 (kubelet)", corev1.ContainerPort{ContainerPort: 10250}, true},
		{"port 10257 (kube-controller-manager)", corev1.ContainerPort{ContainerPort: 10257}, true},
		{"port 10259 (kube-scheduler)", corev1.ContainerPort{ContainerPort: 10259}, true},
		{"port 9091 (Prometheus)", corev1.ContainerPort{ContainerPort: 9091}, true},
		{"port 9092 (Thanos)", corev1.ContainerPort{ContainerPort: 9092}, true},
		{"port 9100 (node-exporter)", corev1.ContainerPort{ContainerPort: 9100}, true},
		{"named https", corev1.ContainerPort{Name: "https", ContainerPort: 7777}, true},
		{"named https-metrics", corev1.ContainerPort{Name: "https-metrics", ContainerPort: 7777}, true},
		{"port 80", corev1.ContainerPort{ContainerPort: 80}, false},
		{"named http", corev1.ContainerPort{Name: "http", ContainerPort: 80}, false},
		{"named grpc", corev1.ContainerPort{Name: "grpc", ContainerPort: 9090}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTLSContainerPort(tt.port)
			if got != tt.want {
				t.Errorf("isTLSContainerPort(%v) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestExtractFromPod_Port443(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.1.5",
		},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.Host != "10.244.1.5" {
		t.Errorf("host = %q, want 10.244.1.5", ep.Host)
	}
	if ep.Port != 443 {
		t.Errorf("port = %d, want 443", ep.Port)
	}
	if ep.SourceKind != securityv1alpha1.SourceKindPod {
		t.Errorf("sourceKind = %q, want Pod", ep.SourceKind)
	}
	if ep.SourceNamespace != "default" {
		t.Errorf("sourceNamespace = %q, want default", ep.SourceNamespace)
	}
	if ep.SourceName != "my-pod" {
		t.Errorf("sourceName = %q, want my-pod", ep.SourceName)
	}
}

func TestExtractFromPod_Port8443(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if endpoints[0].Port != 8443 {
		t.Errorf("port = %d, want 8443", endpoints[0].Port)
	}
}

func TestExtractFromPod_NamedHTTPS(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{Name: "https", ContainerPort: 9443}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if endpoints[0].Port != 9443 {
		t.Errorf("port = %d, want 9443", endpoints[0].Port)
	}
}

func TestExtractFromPod_NotRunning(t *testing.T) {
	phases := []corev1.PodPhase{corev1.PodPending, corev1.PodSucceeded, corev1.PodFailed}
	for _, phase := range phases {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 443}}},
				},
			},
			Status: corev1.PodStatus{Phase: phase, PodIP: "10.244.1.5"},
		}

		endpoints := ExtractFromPod(pod)
		if len(endpoints) != 0 {
			t.Errorf("phase %q: expected 0 endpoints, got %d", phase, len(endpoints))
		}
	}
}

func TestExtractFromPod_NoPodIP(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 443}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ""},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints for pod with no IP, got %d", len(endpoints))
	}
}

func TestExtractFromPod_NonTLSPortsOnly(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 80, Protocol: corev1.ProtocolTCP},
					{ContainerPort: 9090, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints for non-TLS ports, got %d", len(endpoints))
	}
}

func TestExtractFromPod_UDPPort443(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 443, Protocol: corev1.ProtocolUDP},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints for UDP port, got %d", len(endpoints))
	}
}

func TestExtractFromPod_MultipleTLSPorts(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
				}},
				{Name: "sidecar", Ports: []corev1.ContainerPort{
					{ContainerPort: 8443, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}
}

func TestExtractFromPod_DuplicatePortAcrossContainers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
				}},
				{Name: "sidecar", Ports: []corev1.ContainerPort{
					{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (deduplicated), got %d", len(endpoints))
	}
}

func TestExtractFromPod_HostNetwork(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "192.168.1.100"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint for hostNetwork pod, got %d", len(endpoints))
	}
	if endpoints[0].Host != "192.168.1.100" {
		t.Errorf("host = %q, want 192.168.1.100 (node IP)", endpoints[0].Host)
	}
}

func TestExtractFromPod_HTTPProbePortSkipped(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(8443),
								Scheme: corev1.URISchemeHTTP,
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints (HTTP probe port skipped), got %d", len(endpoints))
	}
}

func TestExtractFromPod_HTTPSProbePortKept(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(8443),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (HTTPS probe port kept), got %d", len(endpoints))
	}
	if !endpoints[0].IsProbePort {
		t.Error("expected IsProbePort=true for HTTPS probe port")
	}
}

func TestExtractFromPod_TCPProbePortSkipped(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Ports: []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							TCPSocket: &corev1.TCPSocketAction{
								Port: intstr.FromInt32(443),
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints (TCP probe port skipped), got %d", len(endpoints))
	}
}

func TestExtractFromPod_NonProbePortNotAffected(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(9090),
								Scheme: corev1.URISchemeHTTP,
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (probe on different port), got %d", len(endpoints))
	}
	if endpoints[0].IsProbePort {
		t.Error("expected IsProbePort=false when probe is on a different port")
	}
}

func TestExtractFromPod_NamedProbePort(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					Ports: []corev1.ContainerPort{
						{Name: "https", ContainerPort: 8443, Protocol: corev1.ProtocolTCP},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromString("https"),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (HTTPS named probe port), got %d", len(endpoints))
	}
	if !endpoints[0].IsProbePort {
		t.Error("expected IsProbePort=true for named probe port")
	}
}

func TestExtractFromPod_MultipleProbeTypes(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(8443),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(8443),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
					},
					StartupProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(8443),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if !endpoints[0].IsProbePort {
		t.Error("expected IsProbePort=true")
	}
}

func TestExtractFromPod_MixedHTTPAndHTTPSProbesSamePort(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(8443),
								Scheme: corev1.URISchemeHTTP,
							},
						},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port:   intstr.FromInt32(8443),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (HTTPS wins over HTTP), got %d", len(endpoints))
	}
	if !endpoints[0].IsProbePort {
		t.Error("expected IsProbePort=true")
	}
}

func TestExtractFromPod_GRPCProbePortSkipped(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Ports: []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							GRPC: &corev1.GRPCAction{
								Port: 8443,
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints (gRPC probe port skipped), got %d", len(endpoints))
	}
}

func TestExtractFromPod_IPv6PodIP(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 443}}},
			},
		},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  "fd00::1",
			PodIPs: []corev1.PodIP{{IP: "fd00::1"}},
		},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint for IPv6 pod, got %d", len(endpoints))
	}
	if endpoints[0].Host != "fd00::1" {
		t.Errorf("host = %q, want fd00::1", endpoints[0].Host)
	}
}

func TestExtractFromPod_DualStack(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{{ContainerPort: 443}}},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.1.5",
			PodIPs: []corev1.PodIP{
				{IP: "10.244.1.5"},
				{IP: "fd00::5"},
			},
		},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints for dual-stack pod, got %d", len(endpoints))
	}

	hosts := map[string]bool{}
	for _, ep := range endpoints {
		hosts[ep.Host] = true
	}
	if !hosts["10.244.1.5"] {
		t.Error("missing IPv4 endpoint")
	}
	if !hosts["fd00::5"] {
		t.Error("missing IPv6 endpoint")
	}
}

func TestGenerateCRName_IPv6(t *testing.T) {
	ep := Endpoint{
		Host:            "2001:db8::1",
		Port:            443,
		SourceKind:      securityv1alpha1.SourceKindPod,
		SourceNamespace: "default",
		SourceName:      "my-pod",
	}

	name := GenerateCRName(&ep)

	if len(name) > MaxCRNameLength {
		t.Errorf("name too long: %d > %d", len(name), MaxCRNameLength)
	}
	if strings.Contains(name, ":") {
		t.Errorf("name contains colon: %q", name)
	}
	if !strings.Contains(name, "2001-db8--1") {
		t.Errorf("expected readable IPv6 in name, got: %q", name)
	}
}

func TestExtractFromPod_DefaultProtocol(t *testing.T) {
	// When protocol is not specified, it defaults to TCP
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 443},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint for port with default protocol, got %d", len(endpoints))
	}
}

func TestSetExtraTLSPorts(t *testing.T) {
	defer SetExtraTLSPorts(map[int32]bool{})

	SetExtraTLSPorts(map[int32]bool{12345: true, 54321: true})

	p12345 := corev1.ServicePort{Port: 12345}
	if !isTLSPort(&p12345) {
		t.Error("expected port 12345 to be detected as TLS after SetExtraTLSPorts")
	}
	if !isTLSContainerPort(corev1.ContainerPort{ContainerPort: 54321}) {
		t.Error("expected port 54321 to be detected as TLS after SetExtraTLSPorts")
	}
	p99999 := corev1.ServicePort{Port: 99999}
	if isTLSPort(&p99999) {
		t.Error("unexpected TLS detection for port 99999")
	}
}

func TestExtraTLSPorts_PodExtraction(t *testing.T) {
	defer SetExtraTLSPorts(map[int32]bool{})

	SetExtraTLSPorts(map[int32]bool{7777: true})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 7777, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint for extra TLS port, got %d", len(endpoints))
	}
	if endpoints[0].Port != 7777 {
		t.Errorf("port = %d, want 7777", endpoints[0].Port)
	}
}

func TestSetScanAllPorts(t *testing.T) {
	defer SetScanAllPorts(false)

	if scanAllPortsEnabled() {
		t.Error("expected ScanAllPortsEnabled to be false by default")
	}

	SetScanAllPorts(true)
	if !scanAllPortsEnabled() {
		t.Error("expected ScanAllPortsEnabled to be true after SetScanAllPorts(true)")
	}

	SetScanAllPorts(false)
	if scanAllPortsEnabled() {
		t.Error("expected ScanAllPortsEnabled to be false after SetScanAllPorts(false)")
	}
}

func TestExtractFromPod_ScanAllPorts(t *testing.T) {
	defer SetScanAllPorts(false)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Ports: []corev1.ContainerPort{
					{ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
					{ContainerPort: 9001, Protocol: corev1.ProtocolTCP},
				}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.128.2.24"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 0 {
		t.Fatalf("expected 0 endpoints without scan-all-ports, got %d", len(endpoints))
	}

	SetScanAllPorts(true)
	endpoints = ExtractFromPod(pod)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints with scan-all-ports, got %d", len(endpoints))
	}
	if endpoints[0].Port != 8080 {
		t.Errorf("port = %d, want 8080", endpoints[0].Port)
	}
	if endpoints[1].Port != 9001 {
		t.Errorf("port = %d, want 9001", endpoints[1].Port)
	}
	if endpoints[0].SourceKind != "Pod" {
		t.Errorf("source kind = %s, want Pod", endpoints[0].SourceKind)
	}
}

func TestExtractFromPod_ScanAllPorts_ProbeStillSkipped(t *testing.T) {
	defer SetScanAllPorts(false)
	SetScanAllPorts(true)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "probe-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
						{ContainerPort: 9001, Protocol: corev1.ProtocolTCP},
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Port: intstr.FromInt32(8080),
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.128.2.24"},
	}

	endpoints := ExtractFromPod(pod)
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (probe port 8080 skipped), got %d", len(endpoints))
	}
	if endpoints[0].Port != 9001 {
		t.Errorf("port = %d, want 9001", endpoints[0].Port)
	}
}

func TestIsHeadlessService(t *testing.T) {
	headless := &corev1.Service{Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone}}
	if !IsHeadlessService(headless) {
		t.Error("expected headless service to be detected")
	}
	normal := &corev1.Service{Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.1"}}
	if IsHeadlessService(normal) {
		t.Error("expected normal service to not be headless")
	}
}

func TestExtractFromHeadlessService(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "my-db", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	addresses := []string{"10.244.0.5", "10.244.0.6"}
	endpoints := ExtractFromHeadlessService(svc, addresses)

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints (one per address for port 443), got %d", len(endpoints))
	}
	for _, ep := range endpoints {
		if ep.Port != 443 {
			t.Errorf("port = %d, want 443", ep.Port)
		}
		if ep.SourceKind != securityv1alpha1.SourceKindService {
			t.Errorf("sourceKind = %s, want Service", ep.SourceKind)
		}
	}
}

func TestExtractFromHeadlessService_NoAddresses(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "my-db", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP},
			},
		},
	}

	endpoints := ExtractFromHeadlessService(svc, nil)
	if len(endpoints) != 0 {
		t.Errorf("expected 0 endpoints for nil addresses, got %d", len(endpoints))
	}
}

func TestExtractFromHTTPRoute(t *testing.T) {
	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]interface{}{"name": "r", "namespace": "default"},
		"spec":     map[string]interface{}{"hostnames": []interface{}{"app.example.com"}},
	}}
	eps := ExtractFromHTTPRoute(route)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].SourceKind != securityv1alpha1.SourceKindHTTPRoute {
		t.Errorf("sourceKind = %q, want HTTPRoute", eps[0].SourceKind)
	}
	if eps[0].Host != "app.example.com" {
		t.Errorf("host = %q, want app.example.com", eps[0].Host)
	}
	if eps[0].Port != 443 {
		t.Errorf("port = %d, want 443", eps[0].Port)
	}
	if eps[0].SourceNamespace != "default" {
		t.Errorf("sourceNamespace = %q, want default", eps[0].SourceNamespace)
	}
}

func TestExtractFromHTTPRoute_MultipleHostnames(t *testing.T) {
	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]interface{}{"name": "multi", "namespace": "production"},
		"spec":     map[string]interface{}{"hostnames": []interface{}{"app.example.com", "api.example.com", "admin.example.com"}},
	}}
	eps := ExtractFromHTTPRoute(route)
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints (one per hostname), got %d", len(eps))
	}
	for _, ep := range eps {
		if ep.SourceKind != securityv1alpha1.SourceKindHTTPRoute || ep.SourceName != "multi" || ep.SourceNamespace != "production" {
			t.Errorf("unexpected source info: %+v", ep)
		}
	}
}

func TestExtractFromHTTPRoute_NoHostnames(t *testing.T) {
	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]interface{}{"name": "r", "namespace": "default"},
		"spec":     map[string]interface{}{},
	}}
	eps := ExtractFromHTTPRoute(route)
	if len(eps) != 0 {
		t.Errorf("expected 0 endpoints for HTTPRoute without hostnames, got %d", len(eps))
	}
}

func TestExtractFromTLSRoute(t *testing.T) {
	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1alpha2", "kind": "TLSRoute",
		"metadata": map[string]interface{}{"name": "secure-route", "namespace": "default"},
		"spec":     map[string]interface{}{"hostnames": []interface{}{"secure.example.com"}},
	}}
	eps := ExtractFromTLSRoute(route)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].SourceKind != securityv1alpha1.SourceKindTLSRoute {
		t.Errorf("sourceKind = %q, want TLSRoute", eps[0].SourceKind)
	}
	if eps[0].Host != "secure.example.com" {
		t.Errorf("host = %q, want secure.example.com", eps[0].Host)
	}
	if eps[0].Port != 443 {
		t.Errorf("port = %d, want 443", eps[0].Port)
	}
}

func TestExtractFromTLSRoute_NoHostnames(t *testing.T) {
	route := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1alpha2", "kind": "TLSRoute",
		"metadata": map[string]interface{}{"name": "r", "namespace": "default"},
		"spec":     map[string]interface{}{},
	}}
	eps := ExtractFromTLSRoute(route)
	if len(eps) != 0 {
		t.Errorf("expected 0 endpoints for TLSRoute without hostnames, got %d", len(eps))
	}
}

func TestExtractFromGateway(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]interface{}{"name": "gw", "namespace": "default"},
		"spec": map[string]interface{}{
			"listeners": []interface{}{
				map[string]interface{}{"protocol": "HTTPS", "port": int64(443)},
				map[string]interface{}{"protocol": "HTTP", "port": int64(80)},
			},
		},
		"status": map[string]interface{}{
			"addresses": []interface{}{map[string]interface{}{"value": "10.0.0.1"}},
		},
	}}
	eps := ExtractFromGateway(gw)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint (HTTPS only, not HTTP), got %d", len(eps))
	}
	if eps[0].Host != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1 (from status.addresses)", eps[0].Host)
	}
	if eps[0].Port != 443 {
		t.Errorf("port = %d, want 443", eps[0].Port)
	}
	if eps[0].SourceKind != securityv1alpha1.SourceKindGateway {
		t.Errorf("sourceKind = %q, want Gateway", eps[0].SourceKind)
	}
}

func TestExtractFromGateway_FallbackToName(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]interface{}{"name": "my-gw", "namespace": "default"},
		"spec": map[string]interface{}{
			"listeners": []interface{}{
				map[string]interface{}{"protocol": "HTTPS", "port": int64(8443)},
			},
		},
	}}
	eps := ExtractFromGateway(gw)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].Host != "my-gw" {
		t.Errorf("host = %q, want my-gw (gateway name fallback when no status.addresses)", eps[0].Host)
	}
	if eps[0].Port != 8443 {
		t.Errorf("port = %d, want 8443", eps[0].Port)
	}
}

func TestExtractFromGateway_TLSProtocol(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]interface{}{"name": "gw", "namespace": "default"},
		"spec": map[string]interface{}{
			"listeners": []interface{}{
				map[string]interface{}{"protocol": "TLS", "port": int64(5671)},
			},
		},
		"status": map[string]interface{}{
			"addresses": []interface{}{map[string]interface{}{"value": "10.0.0.2"}},
		},
	}}
	eps := ExtractFromGateway(gw)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint for TLS protocol listener, got %d", len(eps))
	}
	if eps[0].Port != 5671 {
		t.Errorf("port = %d, want 5671", eps[0].Port)
	}
}

func TestExtractFromGateway_NoListeners(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]interface{}{"name": "gw", "namespace": "default"},
		"spec":     map[string]interface{}{},
	}}
	eps := ExtractFromGateway(gw)
	if len(eps) != 0 {
		t.Errorf("expected 0 endpoints for Gateway without listeners, got %d", len(eps))
	}
}

func TestExtractFromGateway_HTTPOnlySkipped(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]interface{}{"name": "gw", "namespace": "default"},
		"spec": map[string]interface{}{
			"listeners": []interface{}{
				map[string]interface{}{"protocol": "HTTP", "port": int64(80)},
				map[string]interface{}{"protocol": "TCP", "port": int64(5432)},
			},
		},
	}}
	eps := ExtractFromGateway(gw)
	if len(eps) != 0 {
		t.Errorf("expected 0 endpoints for HTTP/TCP-only listeners, got %d", len(eps))
	}
}

func TestShouldSkipResource(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{"nil annotations", nil, false},
		{"empty annotations", map[string]string{}, false},
		{"skip true", map[string]string{AnnotationSkip: "true"}, true},
		{"skip false", map[string]string{AnnotationSkip: "false"}, false},
		{"skip empty", map[string]string{AnnotationSkip: ""}, false},
		{"skip True (case sensitive)", map[string]string{AnnotationSkip: "True"}, false},
		{"skip TRUE (case sensitive)", map[string]string{AnnotationSkip: "TRUE"}, false},
		{"unrelated annotation", map[string]string{"other": "true"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldSkipResource(tc.annotations); got != tc.want {
				t.Errorf("ShouldSkipResource() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseExtraPorts(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        []int32
	}{
		{"nil annotations", nil, nil},
		{"empty annotations", map[string]string{}, nil},
		{"no extra-ports", map[string]string{"other": "val"}, nil},
		{"empty value", map[string]string{AnnotationExtraPorts: ""}, nil},
		{"single port", map[string]string{AnnotationExtraPorts: "9443"}, []int32{9443}},
		{"multiple ports", map[string]string{AnnotationExtraPorts: "9443,8443,6443"}, []int32{9443, 8443, 6443}},
		{"with spaces", map[string]string{AnnotationExtraPorts: " 9443 , 8443 "}, []int32{9443, 8443}},
		{"invalid port skipped", map[string]string{AnnotationExtraPorts: "9443,abc,8443"}, []int32{9443, 8443}},
		{"port out of range", map[string]string{AnnotationExtraPorts: "9443,99999,8443"}, []int32{9443, 8443}},
		{"zero port skipped", map[string]string{AnnotationExtraPorts: "0,9443"}, []int32{9443}},
		{"negative port skipped", map[string]string{AnnotationExtraPorts: "-1,9443"}, []int32{9443}},
		{"boundary port 65535", map[string]string{AnnotationExtraPorts: "65535"}, []int32{65535}},
		{"boundary port 65536 rejected", map[string]string{AnnotationExtraPorts: "65536"}, nil},
		{"boundary port 1", map[string]string{AnnotationExtraPorts: "1"}, []int32{1}},
		{"consecutive commas", map[string]string{AnnotationExtraPorts: "9443,,8443"}, []int32{9443, 8443}},
		{"trailing comma", map[string]string{AnnotationExtraPorts: "9443,"}, []int32{9443}},
		{"all invalid", map[string]string{AnnotationExtraPorts: "abc,xyz"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseExtraPorts(tc.annotations)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseExtraPorts() returned %d ports, want %d: %v", len(got), len(tc.want), got)
			}
			for i, p := range got {
				if p != tc.want[i] {
					t.Errorf("port[%d] = %d, want %d", i, p, tc.want[i])
				}
			}
		})
	}
}

func TestExtractFromGateway_MultipleListeners(t *testing.T) {
	gw := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]interface{}{"name": "gw", "namespace": "default"},
		"spec": map[string]interface{}{
			"listeners": []interface{}{
				map[string]interface{}{"protocol": "HTTPS", "port": int64(443)},
				map[string]interface{}{"protocol": "HTTP", "port": int64(80)},
				map[string]interface{}{"protocol": "TLS", "port": int64(8443)},
				map[string]interface{}{"protocol": "HTTPS", "port": int64(9443)},
			},
		},
		"status": map[string]interface{}{
			"addresses": []interface{}{map[string]interface{}{"value": "10.0.0.1"}},
		},
	}}
	eps := ExtractFromGateway(gw)
	if len(eps) != 3 {
		t.Fatalf("expected 3 TLS endpoints (HTTPS+TLS+HTTPS), got %d", len(eps))
	}
}
