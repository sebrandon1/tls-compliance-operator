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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TLSComplianceTargetSpec defines the desired state of TLSComplianceTarget
type TLSComplianceTargetSpec struct {
	// Host is the hostname or IP to scan
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// Port is the port number to scan
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tlstarget
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.spec.port`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TLSComplianceTarget is the Schema for the tlscompliancetargets API.
// It declares an arbitrary host:port target for TLS compliance scanning.
type TLSComplianceTarget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the target to scan
	// +required
	Spec TLSComplianceTargetSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// TLSComplianceTargetList contains a list of TLSComplianceTarget
type TLSComplianceTargetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSComplianceTarget `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TLSComplianceTarget{}, &TLSComplianceTargetList{})
}
