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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodWorkloadOwner(t *testing.T) {
	controller := true
	falseVal := false

	tests := []struct {
		name     string
		owners   []metav1.OwnerReference
		wantKind string
		wantName string
	}{
		{
			name:     "no owner",
			wantKind: "",
			wantName: "",
		},
		{
			name: "controller reference wins",
			owners: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-6b7f9c4d5", Controller: &falseVal},
				{Kind: "DaemonSet", Name: "node-agent", Controller: &controller},
			},
			wantKind: "DaemonSet",
			wantName: "node-agent",
		},
		{
			name: "falls back to the first reference without a controller flag",
			owners: []metav1.OwnerReference{
				{Kind: "Job", Name: "backup-12345"},
			},
			wantKind: "Job",
			wantName: "backup-12345",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{OwnerReferences: tc.owners}}
			kind, name := podWorkloadOwner(pod)
			if kind != tc.wantKind || name != tc.wantName {
				t.Errorf("podWorkloadOwner() = (%q, %q), want (%q, %q)", kind, name, tc.wantKind, tc.wantName)
			}
		})
	}
}
