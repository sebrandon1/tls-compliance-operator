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

// TLSSecurityProfileSpec declares a cluster-defined TLS security profile that
// endpoints can be evaluated against, in addition to the built-in OpenShift
// Old, Intermediate, and Modern profiles.
type TLSSecurityProfileSpec struct {
	// MinTLSVersion is the lowest acceptable TLS protocol version, using the
	// OpenShift spelling (for example VersionTLS12).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=VersionTLS10;VersionTLS11;VersionTLS12;VersionTLS13
	MinTLSVersion string `json:"minTLSVersion"`

	// Ciphers lists the allowed cipher suites in OpenSSL naming (for example
	// ECDHE-RSA-AES128-GCM-SHA256). Empty means ciphers are not checked.
	// +optional
	Ciphers []string `json:"ciphers,omitempty"`

	// Groups lists the allowed TLS key exchange groups (for example
	// X25519, secp256r1). Empty means groups are not checked.
	// +optional
	Groups []string `json:"groups,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tlsprofile
// +kubebuilder:printcolumn:name="Min Version",type=string,JSONPath=`.spec.minTLSVersion`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TLSSecurityProfile is the Schema for the tlssecurityprofiles API.
// Select one with the operator's --custom-profile flag.
type TLSSecurityProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the profile's minimum version and allowed suites
	// +required
	Spec TLSSecurityProfileSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// TLSSecurityProfileList contains a list of TLSSecurityProfile
type TLSSecurityProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSSecurityProfile `json:"items"`
}
