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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func BenchmarkExtractFromService(b *testing.B) {
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

	b.ResetTimer()
	for b.Loop() {
		_ = ExtractFromService(svc)
	}
}

func BenchmarkExtractFromPod(b *testing.B) {
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
						{ContainerPort: 80, Protocol: corev1.ProtocolTCP},
						{ContainerPort: 443, Protocol: corev1.ProtocolTCP},
					},
				},
				{
					Name: "sidecar",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8443, Protocol: corev1.ProtocolTCP},
						{Name: "https-metrics", ContainerPort: 9443, Protocol: corev1.ProtocolTCP},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.1.5",
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = ExtractFromPod(pod)
	}
}

func BenchmarkGenerateCRName(b *testing.B) {
	ep := Endpoint{
		Host:            "my-service.default",
		Port:            443,
		SourceKind:      "Service",
		SourceNamespace: "default",
		SourceName:      "my-service",
	}

	b.ResetTimer()
	for b.Loop() {
		_ = GenerateCRName(ep)
	}
}

func BenchmarkGenerateCRName_LongHost(b *testing.B) {
	ep := Endpoint{
		Host:            "very-long-service-name-that-exceeds-normal-limits.very-long-namespace-name",
		Port:            443,
		SourceKind:      "Service",
		SourceNamespace: "very-long-namespace-name",
		SourceName:      "very-long-service-name-that-exceeds-normal-limits",
	}

	b.ResetTimer()
	for b.Loop() {
		_ = GenerateCRName(ep)
	}
}

func BenchmarkIsTLSPort(b *testing.B) {
	ports := []corev1.ServicePort{
		{Port: 443},
		{Port: 8443},
		{Name: "https", Port: 9090},
		{Name: "https-metrics", Port: 9443},
		{Port: 80},
		{Name: "http", Port: 80},
		{Name: "grpc", Port: 9090},
	}

	b.ResetTimer()
	for b.Loop() {
		for i := range ports {
			_ = isTLSPort(ports[i])
		}
	}
}

func BenchmarkIsTLSContainerPort(b *testing.B) {
	ports := []corev1.ContainerPort{
		{ContainerPort: 443},
		{ContainerPort: 8443},
		{Name: "https", ContainerPort: 9090},
		{Name: "https-metrics", ContainerPort: 9443},
		{ContainerPort: 80},
		{Name: "http", ContainerPort: 80},
		{Name: "grpc", ContainerPort: 9090},
	}

	b.ResetTimer()
	for b.Loop() {
		for i := range ports {
			_ = isTLSContainerPort(ports[i])
		}
	}
}
