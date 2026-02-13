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

// SourceKind indicates the type of Kubernetes resource that exposed the endpoint
// +kubebuilder:validation:Enum=Service;Ingress;Route
type SourceKind string

const (
	SourceKindService SourceKind = "Service"
	SourceKindIngress SourceKind = "Ingress"
	SourceKindRoute   SourceKind = "Route"
)

// ComplianceStatus indicates the TLS compliance status of an endpoint
// +kubebuilder:validation:Enum=Compliant;NonCompliant;Warning;Unreachable;NoTLS;MutualTLSRequired;Pending;Unknown
type ComplianceStatus string

const (
	// ComplianceStatusCompliant means TLS 1.3 supported AND no TLS 1.0/1.1
	ComplianceStatusCompliant ComplianceStatus = "Compliant"
	// ComplianceStatusNonCompliant means TLS 1.0 or 1.1 is supported
	ComplianceStatusNonCompliant ComplianceStatus = "NonCompliant"
	// ComplianceStatusWarning means TLS 1.3 not supported but no legacy TLS
	ComplianceStatusWarning ComplianceStatus = "Warning"
	// ComplianceStatusUnreachable means the endpoint could not be reached
	ComplianceStatusUnreachable ComplianceStatus = "Unreachable"
	// ComplianceStatusNoTLS means the port is open but does not speak TLS
	ComplianceStatusNoTLS ComplianceStatus = "NoTLS"
	// ComplianceStatusMutualTLSRequired means the server requires a client certificate
	ComplianceStatusMutualTLSRequired ComplianceStatus = "MutualTLSRequired"
	// ComplianceStatusPending means the check has not been performed yet
	ComplianceStatusPending ComplianceStatus = "Pending"
	// ComplianceStatusUnknown is the default status
	ComplianceStatusUnknown ComplianceStatus = "Unknown"
)

// TLSVersionSupport indicates which TLS versions an endpoint supports
type TLSVersionSupport struct {
	// TLS10 indicates if TLS 1.0 is supported
	// +optional
	TLS10 bool `json:"tls10,omitempty"`
	// TLS11 indicates if TLS 1.1 is supported
	// +optional
	TLS11 bool `json:"tls11,omitempty"`
	// TLS12 indicates if TLS 1.2 is supported
	// +optional
	TLS12 bool `json:"tls12,omitempty"`
	// TLS13 indicates if TLS 1.3 is supported
	// +optional
	TLS13 bool `json:"tls13,omitempty"`
}

// CertificateInfo contains details about the TLS certificate
type CertificateInfo struct {
	// Issuer is the certificate issuer
	// +optional
	Issuer string `json:"issuer,omitempty"`
	// Subject is the certificate subject
	// +optional
	Subject string `json:"subject,omitempty"`
	// NotBefore is the start of the certificate's validity period
	// +optional
	NotBefore *metav1.Time `json:"notBefore,omitempty"`
	// NotAfter is the end of the certificate's validity period
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
	// DNSNames lists the DNS names in the certificate's SAN
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`
	// IsExpired indicates if the certificate has expired
	// +optional
	IsExpired bool `json:"isExpired,omitempty"`
	// DaysUntilExpiry is the number of days until the certificate expires
	// +optional
	DaysUntilExpiry *int `json:"daysUntilExpiry,omitempty"`
}

// TLSComplianceReportSpec defines the desired state of TLSComplianceReport
type TLSComplianceReportSpec struct {
	// Host is the hostname or IP being checked
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// Port is the port number being checked
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// SourceKind is the type of Kubernetes resource that exposed this endpoint
	// +kubebuilder:validation:Required
	SourceKind SourceKind `json:"sourceKind"`

	// SourceNamespace is the namespace of the source resource
	// +kubebuilder:validation:Required
	SourceNamespace string `json:"sourceNamespace"`

	// SourceName is the name of the source resource
	// +kubebuilder:validation:Required
	SourceName string `json:"sourceName"`
}

// TLSComplianceReportStatus defines the observed state of TLSComplianceReport
type TLSComplianceReportStatus struct {
	// ComplianceStatus indicates the overall TLS compliance status
	// +kubebuilder:default=Unknown
	ComplianceStatus ComplianceStatus `json:"complianceStatus,omitempty"`

	// TLSVersions indicates which TLS versions are supported
	// +optional
	TLSVersions TLSVersionSupport `json:"tlsVersions,omitempty"`

	// CipherSuites maps TLS version to supported cipher suite names
	// +optional
	CipherSuites map[string][]string `json:"cipherSuites,omitempty"`

	// NegotiatedCurves maps TLS version to the negotiated key exchange curve
	// (e.g. X25519, P-256, X25519MLKEM768)
	// +optional
	NegotiatedCurves map[string]string `json:"negotiatedCurves,omitempty"`

	// CertificateInfo contains details about the TLS certificate
	// +optional
	CertificateInfo *CertificateInfo `json:"certificateInfo,omitempty"`

	// LastCheckAt is when the last TLS check was performed
	// +optional
	LastCheckAt *metav1.Time `json:"lastCheckAt,omitempty"`

	// FirstSeenAt is when this endpoint was first discovered
	// +optional
	FirstSeenAt *metav1.Time `json:"firstSeenAt,omitempty"`

	// LastSeenAt is when this endpoint was last observed
	// +optional
	LastSeenAt *metav1.Time `json:"lastSeenAt,omitempty"`

	// CheckCount is the number of TLS checks performed
	// +optional
	CheckCount int64 `json:"checkCount,omitempty"`

	// ConsecutiveErrors is the number of consecutive check errors
	// +optional
	ConsecutiveErrors int `json:"consecutiveErrors,omitempty"`

	// LastError is the last error message from a TLS check
	// +optional
	LastError string `json:"lastError,omitempty"`

	// Conditions represent the current state of the TLSComplianceReport resource
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=tlsreport
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.spec.port`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.sourceKind`
// +kubebuilder:printcolumn:name="Compliance",type=string,JSONPath=`.status.complianceStatus`
// +kubebuilder:printcolumn:name="TLS1.3",type=boolean,JSONPath=`.status.tlsVersions.tls13`
// +kubebuilder:printcolumn:name="TLS1.2",type=boolean,JSONPath=`.status.tlsVersions.tls12`
// +kubebuilder:printcolumn:name="TLS1.0",type=boolean,JSONPath=`.status.tlsVersions.tls10`
// +kubebuilder:printcolumn:name="CertExpiry",type=integer,JSONPath=`.status.certificateInfo.daysUntilExpiry`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TLSComplianceReport is the Schema for the tlscompliancereports API
type TLSComplianceReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of TLSComplianceReport
	// +required
	Spec TLSComplianceReportSpec `json:"spec"`

	// Status defines the observed state of TLSComplianceReport
	// +optional
	Status TLSComplianceReportStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TLSComplianceReportList contains a list of TLSComplianceReport
type TLSComplianceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSComplianceReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TLSComplianceReport{}, &TLSComplianceReportList{})
}
