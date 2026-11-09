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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

type fakeProcNetReader struct {
	content string
	err     error
}

func (f *fakeProcNetReader) ReadProcNet(context.Context, string, string, string) (string, error) {
	return f.content, f.err
}

func discoveryPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-0", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.5"},
	}
}

func TestPodEndpoints_DisabledUsesDeclaredPorts(t *testing.T) {
	r := &EndpointReconciler{ProcNetReader: &fakeProcNetReader{content: "do not read"}}
	pod := discoveryPod()

	if got := r.podEndpoints(context.Background(), pod); len(got) != 0 {
		t.Errorf("podEndpoints() = %+v, want none from declared ports", got)
	}
}

func TestPodEndpoints_DiscoverUndeclaredPort(t *testing.T) {
	// 9443 = 0x24E3, in LISTEN state.
	content := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:24E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 0 100 0 0 10 0\n"
	r := &EndpointReconciler{
		DiscoverListeningPorts: true,
		ProcNetReader:          &fakeProcNetReader{content: content},
	}

	endpoints := r.podEndpoints(context.Background(), discoveryPod())
	if len(endpoints) != 1 || endpoints[0].Port != 9443 {
		t.Fatalf("podEndpoints() = %+v, want the discovered 9443 endpoint", endpoints)
	}
	if endpoints[0].SourceKind != securityv1alpha1.SourceKindPod {
		t.Errorf("SourceKind = %q, want Pod", endpoints[0].SourceKind)
	}
}

func TestPodEndpoints_ExecFailureFallsBackToDeclaredPorts(t *testing.T) {
	pod := discoveryPod()
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8443, Protocol: corev1.ProtocolTCP}}
	r := &EndpointReconciler{
		DiscoverListeningPorts: true,
		ProcNetReader:          &fakeProcNetReader{err: errors.New("exec denied")},
	}

	endpoints := r.podEndpoints(context.Background(), pod)
	if len(endpoints) != 1 || endpoints[0].Port != 8443 {
		t.Fatalf("podEndpoints() = %+v, want the declared 8443 endpoint on failure", endpoints)
	}
}

func TestPodEndpoints_NoReaderUsesDeclaredPorts(t *testing.T) {
	pod := discoveryPod()
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 443, Protocol: corev1.ProtocolTCP}}
	r := &EndpointReconciler{DiscoverListeningPorts: true}

	if got := r.podEndpoints(context.Background(), pod); len(got) != 1 || got[0].Port != 443 {
		t.Errorf("podEndpoints() = %+v, want the declared 443 endpoint", got)
	}
}
