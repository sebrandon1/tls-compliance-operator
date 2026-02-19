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
	if ep.SourceKind != "Service" {
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
	if endpoints[0].SourceKind != "Ingress" {
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
	if ep.SourceKind != "Route" {
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
		SourceKind:      "Service",
		SourceNamespace: "default",
		SourceName:      "my-service",
	}

	name := GenerateCRName(ep)

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
	name2 := GenerateCRName(ep)
	if name != name2 {
		t.Errorf("GenerateCRName is not deterministic: %s != %s", name, name2)
	}
}

func TestGenerateCRName_Uniqueness(t *testing.T) {
	ep1 := Endpoint{
		Host:            "service.default",
		Port:            443,
		SourceKind:      "Service",
		SourceNamespace: "default",
		SourceName:      "service-a",
	}
	ep2 := Endpoint{
		Host:            "service.default",
		Port:            443,
		SourceKind:      "Service",
		SourceNamespace: "default",
		SourceName:      "service-b",
	}

	name1 := GenerateCRName(ep1)
	name2 := GenerateCRName(ep2)

	if name1 == name2 {
		t.Errorf("different endpoints should produce different names: %s", name1)
	}
}

func TestGenerateCRName_LongHost(t *testing.T) {
	ep := Endpoint{
		Host:            "very-long-service-name-that-exceeds-normal-limits.very-long-namespace",
		Port:            443,
		SourceKind:      "Service",
		SourceNamespace: "very-long-namespace",
		SourceName:      "very-long-service-name-that-exceeds-normal-limits",
	}

	name := GenerateCRName(ep)
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
		{"named https", corev1.ServicePort{Name: "https", Port: 9090}, true},
		{"named https-metrics", corev1.ServicePort{Name: "https-metrics", Port: 9443}, true},
		{"port 80", corev1.ServicePort{Port: 80}, false},
		{"named http", corev1.ServicePort{Name: "http", Port: 80}, false},
		{"named grpc", corev1.ServicePort{Name: "grpc", Port: 9090}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTLSPort(tt.port)
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
		{"named https", corev1.ContainerPort{Name: "https", ContainerPort: 9090}, true},
		{"named https-metrics", corev1.ContainerPort{Name: "https-metrics", ContainerPort: 9443}, true},
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
	if ep.SourceKind != "Pod" {
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
