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
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
)

type fakeProcNetReader struct {
	content     string
	err         error
	byContainer map[string]string
	errs        map[string]error
	calls       []string
}

func (f *fakeProcNetReader) ReadProcNet(_ context.Context, _, _, container string) (string, error) {
	f.calls = append(f.calls, container)
	if f.errs != nil {
		if err, ok := f.errs[container]; ok {
			return "", err
		}
	}
	if f.byContainer != nil {
		if content, ok := f.byContainer[container]; ok {
			return content, nil
		}
	}
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
	// 9443 = 0x24E3, in LISTEN state, bound to 127.0.0.1.
	content := "  sl  local_address rem_address   st\n" +
		"   0: 0100007F:24E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 0 100 0 0 10 0\n"
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
	if !endpoints[0].ListenAddressesKnown {
		t.Error("ListenAddressesKnown = false, want true")
	}
	if want := []string{"127.0.0.1"}; !reflect.DeepEqual(endpoints[0].ListenAddresses, want) {
		t.Errorf("ListenAddresses = %v, want %v", endpoints[0].ListenAddresses, want)
	}
}

func TestPodEndpoints_StopsAfterFirstSuccessfulContainer(t *testing.T) {
	// 9443 = 0x24E3 (loopback), 8443 = 0x20FB (wildcard). The containers share
	// the pod network namespace, so the first success is authoritative.
	loopback := "  sl  local_address rem_address   st\n" +
		"   0: 0100007F:24E3 00000000:0000 0A 0 0 1 1 0 0 100 0 0 10 0\n"
	wildcard := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:20FB 00000000:0000 0A 0 0 1 1 0 0 100 0 0 10 0\n"
	reader := &fakeProcNetReader{byContainer: map[string]string{"server": loopback, "sidecar": wildcard}}
	pod := discoveryPod()
	pod.Spec.Containers = []corev1.Container{{Name: "server"}, {Name: "sidecar"}}
	r := &EndpointReconciler{DiscoverListeningPorts: true, ProcNetReader: reader}

	endpoints := r.podEndpoints(context.Background(), pod)
	if len(endpoints) != 1 || endpoints[0].Port != 9443 {
		t.Fatalf("podEndpoints() = %+v, want only the first container's 9443 listener", endpoints)
	}
	if want := []string{"127.0.0.1"}; !reflect.DeepEqual(endpoints[0].ListenAddresses, want) {
		t.Errorf("ListenAddresses = %v, want %v", endpoints[0].ListenAddresses, want)
	}
	if want := []string{"server"}; !reflect.DeepEqual(reader.calls, want) {
		t.Errorf("ReadProcNet calls = %v, want %v", reader.calls, want)
	}
}

func TestPodEndpoints_OneContainerFailingStillUsesListeners(t *testing.T) {
	// The first container is distroless and cannot run cat; the sidecar can.
	sidecar := "  sl  local_address rem_address   st\n" +
		"   0: 0100007F:24E3 00000000:0000 0A 0 0 1 1 0 0 100 0 0 10 0\n"
	reader := &fakeProcNetReader{
		byContainer: map[string]string{"sidecar": sidecar},
		errs:        map[string]error{"server": errors.New("exec: \"cat\": executable file not found")},
	}
	pod := discoveryPod()
	pod.Spec.Containers = []corev1.Container{{Name: "server"}, {Name: "sidecar"}}
	r := &EndpointReconciler{DiscoverListeningPorts: true, ProcNetReader: reader}

	endpoints := r.podEndpoints(context.Background(), pod)
	if len(endpoints) != 1 || !endpoint.IsLoopbackOnly(endpoints[0].ListenAddresses) {
		t.Fatalf("podEndpoints() = %+v, want the sidecar's loopback listener", endpoints)
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
