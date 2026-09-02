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
// +kubebuilder:validation:Enum=Service;Ingress;Route;Target;Pod;HTTPRoute;TLSRoute;GRPCRoute;Gateway
type SourceKind string

const (
	SourceKindService   SourceKind = "Service"
	SourceKindIngress   SourceKind = "Ingress"
	SourceKindRoute     SourceKind = "Route"
	SourceKindTarget    SourceKind = "Target"
	SourceKindPod       SourceKind = "Pod"
	SourceKindHTTPRoute SourceKind = "HTTPRoute"
	SourceKindTLSRoute  SourceKind = "TLSRoute"
	SourceKindGRPCRoute SourceKind = "GRPCRoute"
	SourceKindGateway   SourceKind = "Gateway"
)

// RescanAnnotation is the TLSComplianceReport annotation the kubectl plugin
// sets to request an immediate re-check. The controller removes it after the
// scan starts.
const RescanAnnotation = "tls-compliance.telco.openshift.io/rescan"

// ComplianceStatus indicates the TLS compliance status of an endpoint
// +kubebuilder:validation:Enum=Compliant;NonCompliant;Warning;Unreachable;Timeout;Closed;Filtered;NoTLS;PlaintextHTTP;MutualTLSRequired;Pending;Unknown
type ComplianceStatus string

const (
	// ComplianceStatusCompliant means TLS 1.2 or 1.3 is supported (legacy versions alongside are acceptable)
	ComplianceStatusCompliant ComplianceStatus = "Compliant"
	// ComplianceStatusNonCompliant means only legacy TLS (1.0/1.1/SSL 3.0) is supported with no TLS 1.2 or 1.3
	ComplianceStatusNonCompliant ComplianceStatus = "NonCompliant"
	// ComplianceStatusWarning means the endpoint supports modern TLS (1.2/1.3) but also allows legacy versions (SSL 3.0/TLS 1.0/1.1)
	ComplianceStatusWarning ComplianceStatus = "Warning"
	// ComplianceStatusUnreachable means the endpoint could not be reached (generic failure)
	ComplianceStatusUnreachable ComplianceStatus = "Unreachable"
	// ComplianceStatusTimeout means the connection timed out waiting for a response
	ComplianceStatusTimeout ComplianceStatus = "Timeout"
	// ComplianceStatusClosed means the port is not listening (connection refused)
	ComplianceStatusClosed ComplianceStatus = "Closed"
	// ComplianceStatusFiltered is reserved for future use — mapped but not currently produced by the checker
	ComplianceStatusFiltered ComplianceStatus = "Filtered"
	// ComplianceStatusNoTLS means the port is open but does not speak TLS
	ComplianceStatusNoTLS ComplianceStatus = "NoTLS"
	// ComplianceStatusPlaintextHTTP means the port is serving plaintext HTTP without TLS
	ComplianceStatusPlaintextHTTP ComplianceStatus = "PlaintextHTTP"
	// ComplianceStatusMutualTLSRequired means the server requires a client certificate
	ComplianceStatusMutualTLSRequired ComplianceStatus = "MutualTLSRequired"
	// ComplianceStatusPending means the check has not been performed yet
	ComplianceStatusPending ComplianceStatus = "Pending"
	// ComplianceStatusUnknown is the default status
	ComplianceStatusUnknown ComplianceStatus = "Unknown"
)

// PQCReadiness indicates the post-quantum cryptography readiness level of an endpoint.
// Modeled after the classification used by the upstream OpenShift tls-scanner.
// +kubebuilder:validation:Enum=PQCReady;TLS13Capable;LegacyTLS;NoPQC
type PQCReadiness string

const (
	// PQCReadinessPQCReady means the endpoint supports TLS 1.3 with a hybrid
	// ML-KEM key exchange (e.g. X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)
	PQCReadinessPQCReady PQCReadiness = "PQCReady"
	// PQCReadinessTLS13Capable means the endpoint supports TLS 1.3 but has not
	// negotiated a post-quantum key exchange algorithm
	PQCReadinessTLS13Capable PQCReadiness = "TLS13Capable"
	// PQCReadinessLegacyTLS means the endpoint only supports TLS 1.2 or older
	PQCReadinessLegacyTLS PQCReadiness = "LegacyTLS"
	// PQCReadinessNoPQC means no TLS was detected on the endpoint
	PQCReadinessNoPQC PQCReadiness = "NoPQC"
)

// TLSVersionSupport indicates which SSL/TLS versions an endpoint supports
type TLSVersionSupport struct {
	// SSL30 indicates if the deprecated SSLv3 protocol is supported
	// +optional
	SSL30 bool `json:"ssl30"`
	// TLS10 indicates if TLS 1.0 is supported
	TLS10 bool `json:"tls10"`
	// TLS11 indicates if TLS 1.1 is supported
	TLS11 bool `json:"tls11"`
	// TLS12 indicates if TLS 1.2 is supported
	TLS12 bool `json:"tls12"`
	// TLS13 indicates if TLS 1.3 is supported
	TLS13 bool `json:"tls13"`
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
	DaysUntilExpiry int `json:"daysUntilExpiry"`
	// HostnameMatch indicates whether the certificate is valid for the tested endpoint hostname
	// +optional
	HostnameMatch *bool `json:"hostnameMatch,omitempty"`
	// ChainLength is the number of certificates in the peer certificate chain
	// +optional
	ChainLength int `json:"chainLength,omitempty"`
	// PublicKeyAlgorithm is the certificate's public key algorithm (e.g. RSA, ECDSA, Ed25519)
	// +optional
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm,omitempty"`
	// PublicKeyBits is the size of the public key in bits
	// +optional
	PublicKeyBits int `json:"publicKeyBits,omitempty"`
	// SignatureAlgorithm is the algorithm used to sign the certificate (e.g. SHA256-RSA, ECDSA-SHA256)
	// +optional
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	// SerialNumber is the certificate serial number in lowercase hex
	// +optional
	SerialNumber string `json:"serialNumber,omitempty"`
	// Fingerprint is the SHA-256 digest of the DER-encoded certificate, lowercase hex
	// +optional
	Fingerprint string `json:"fingerprint,omitempty"`
	// IPAddresses lists IP SANs on the certificate
	// +optional
	IPAddresses []string `json:"ipAddresses,omitempty"`
}

// TLSProfileComplianceResult contains the result of checking an endpoint
// against an OpenShift TLS security profile
type TLSProfileComplianceResult struct {
	// ProfileType is the configured profile type (Old, Intermediate, Modern, Custom)
	ProfileType string `json:"profileType"`
	// Compliant indicates whether the endpoint meets the profile requirements
	Compliant bool `json:"compliant"`
	// MinTLSVersionMet indicates whether the endpoint does not support TLS versions
	// below the profile's minimum
	MinTLSVersionMet bool `json:"minTLSVersionMet"`
	// DisallowedCiphers lists cipher suites negotiated by the endpoint that are
	// not in the profile's allowed list
	// +optional
	DisallowedCiphers []string `json:"disallowedCiphers,omitempty"`
	// GroupsCompliant indicates whether the endpoint's negotiated curves are
	// in the profile's allowed groups list
	GroupsCompliant bool `json:"groupsCompliant"`
	// DisallowedGroups lists key exchange groups negotiated by the endpoint
	// that are not in the profile's allowed list
	// +optional
	DisallowedGroups []string `json:"disallowedGroups,omitempty"`
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

// ComplianceHistoryEntry represents a single historical TLS scan result
type ComplianceHistoryEntry struct {
	// Timestamp is when the check was performed
	// +optional
	Timestamp *metav1.Time `json:"timestamp,omitempty"`
	// ComplianceStatus is the TLS compliance status at that time
	ComplianceStatus ComplianceStatus `json:"complianceStatus"`
	// OverallCipherGrade is the worst grade across all negotiated cipher suites
	// +optional
	OverallCipherGrade string `json:"overallCipherGrade,omitempty"`
	// TLSVersions indicates which TLS versions were supported
	// +optional
	TLSVersions TLSVersionSupport `json:"tlsVersions,omitempty"`
	// CertFingerprint is the SHA-256 digest of the certificate fingerprint
	// +optional
	CertFingerprint string `json:"certFingerprint,omitempty"`
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

	// CipherStrengthGrades maps each cipher suite name to its strength grade (A-F)
	// +optional
	CipherStrengthGrades map[string]string `json:"cipherStrengthGrades,omitempty"`

	// OverallCipherGrade is the worst grade across all negotiated cipher suites
	// +optional
	OverallCipherGrade string `json:"overallCipherGrade,omitempty"`

	// ForwardSecrecy indicates whether all negotiated cipher suites use
	// ephemeral key exchange (ECDHE/DHE), providing perfect forward secrecy
	// +optional
	ForwardSecrecy bool `json:"forwardSecrecy"`

	// KeyExchangeTypes maps TLS version to the key exchange algorithm used
	// (ECDHE, DHE, RSA, or TLS13)
	// +optional
	KeyExchangeTypes map[string]string `json:"keyExchangeTypes,omitempty"`

	// ALPNProtocols maps TLS version to the negotiated ALPN protocol
	// (e.g. "h2", "http/1.1")
	// +optional
	ALPNProtocols map[string]string `json:"alpnProtocols,omitempty"`

	// NegotiatedCurves maps TLS version to the negotiated key exchange curve
	// (e.g. X25519, P-256, X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)
	// +optional
	NegotiatedCurves map[string]string `json:"negotiatedCurves,omitempty"`

	// QuantumReady indicates whether any TLS connection negotiated a
	// hybrid ML-KEM key exchange (e.g. X25519MLKEM768, SecP256r1MLKEM768)
	// +optional
	QuantumReady bool `json:"quantumReady"`

	// MLKEMSupported indicates whether the endpoint accepted a hybrid ML-KEM
	// key exchange when explicitly offered via active probing
	// +optional
	MLKEMSupported bool `json:"mlkemSupported"`

	// PQCReadiness classifies the endpoint's post-quantum cryptography readiness:
	// PQCReady (TLS 1.3 + hybrid ML-KEM), TLS13Capable (TLS 1.3 without ML-KEM),
	// LegacyTLS (TLS 1.2 or older only), or NoPQC (no TLS detected)
	// +optional
	PQCReadiness PQCReadiness `json:"pqcReadiness,omitempty"`

	// FIPSDetected indicates whether the operator detected FIPS mode on the cluster.
	// When true, ML-KEM key exchange is unavailable due to FIPS restrictions.
	// +optional
	FIPSDetected bool `json:"fipsDetected,omitempty"`

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

	// ScanDuration is the wall-clock time taken by the last TLS check (e.g. "1.23s")
	// +optional
	ScanDuration string `json:"scanDuration,omitempty"`

	// ConsecutiveErrors is the number of consecutive check errors
	// +optional
	ConsecutiveErrors int `json:"consecutiveErrors,omitempty"`

	// LastError is the last error message from a TLS check
	// +optional
	LastError string `json:"lastError,omitempty"`

	// History contains a bounded audit trail of previous scan results
	// +optional
	// +listType=atomic
	History []ComplianceHistoryEntry `json:"history,omitempty"`

	// RetryCount is the current retry attempt number for transient failures
	// +optional
	RetryCount int `json:"retryCount,omitempty"`

	// NextRetryAt is when the next retry attempt will happen
	// +optional
	NextRetryAt *metav1.Time `json:"nextRetryAt,omitempty"`

	// IngressProfileCompliance contains the compliance result against the
	// OpenShift IngressController TLS security profile (OpenShift only)
	// +optional
	IngressProfileCompliance *TLSProfileComplianceResult `json:"ingressProfileCompliance,omitempty"`

	// APIServerProfileCompliance contains the compliance result against the
	// OpenShift APIServer TLS security profile (OpenShift only)
	// +optional
	APIServerProfileCompliance *TLSProfileComplianceResult `json:"apiServerProfileCompliance,omitempty"`

	// KubeletProfileCompliance contains the compliance result against the
	// OpenShift KubeletConfig TLS security profile (OpenShift only)
	// +optional
	KubeletProfileCompliance *TLSProfileComplianceResult `json:"kubeletProfileCompliance,omitempty"`

	// TLSAdherence is the OpenShift APIServer TLS adherence mode
	// (e.g. LegacyAdheringComponentsOnly, StrictAllComponents).
	// Empty on non-OpenShift clusters or when the field is not set.
	// +optional
	TLSAdherence string `json:"tlsAdherence,omitempty"`

	// Conditions represent the current state of the TLSComplianceReport resource
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ImageCertificationInfo contains image certification data cross-referenced from
	// imagecertinfo-operator. Only populated when sourceKind=Pod and imagecertinfo-operator
	// is installed in the cluster.
	// +optional
	ImageCertificationInfo []ContainerImageCertInfo `json:"imageCertificationInfo,omitempty"`
}

// ContainerImageCertInfo holds certification data for one container image,
// sourced from a corresponding ImageCertificationInfo CR (imagecertinfo-operator).
type ContainerImageCertInfo struct {
	// ContainerName is the name of the container within the pod
	ContainerName string `json:"containerName"`

	// ImageRef is the full image reference (registry/repository@sha256:...)
	ImageRef string `json:"imageRef"`

	// ICIName is the name of the ImageCertificationInfo CR that was cross-referenced
	// +optional
	ICIName string `json:"iciName,omitempty"`

	// CertificationStatus is the certification status from imagecertinfo-operator
	// (e.g. Certified, NotCertified, Unknown, Error)
	// +optional
	CertificationStatus string `json:"certificationStatus,omitempty"`

	// HealthIndex is the image health grade (A-F) from Red Hat Pyxis
	// +optional
	HealthIndex string `json:"healthIndex,omitempty"`

	// CriticalCVECount is the number of critical vulnerabilities reported by Pyxis
	// +optional
	CriticalCVECount *int `json:"criticalCveCount,omitempty"`

	// DaysUntilEOL is the number of days until end-of-life (negative if past EOL)
	// +optional
	DaysUntilEOL *int `json:"daysUntilEol,omitempty"`

	// RegistryType is the registry type (RedHat, Partner, Community, Private, Unknown)
	// +optional
	RegistryType string `json:"registryType,omitempty"`

	// ICIOperatorVersion is the version of imagecertinfo-operator that produced this data
	// +optional
	ICIOperatorVersion string `json:"iciOperatorVersion,omitempty"`

	// ImportantCVECount is the number of important-severity vulnerabilities from Pyxis
	// +optional
	ImportantCVECount *int `json:"importantCveCount,omitempty"`

	// ModerateCVECount is the number of moderate-severity vulnerabilities from Pyxis
	// +optional
	ModerateCVECount *int `json:"moderateCveCount,omitempty"`

	// LowCVECount is the number of low-severity vulnerabilities from Pyxis
	// +optional
	LowCVECount *int `json:"lowCveCount,omitempty"`

	// Publisher is the image publisher from Pyxis (e.g. "Red Hat, Inc.")
	// +optional
	Publisher string `json:"publisher,omitempty"`

	// ReleaseCategory is the Pyxis release category (e.g. "Generally Available", "Tech Preview", "Deprecated")
	// +optional
	ReleaseCategory string `json:"releaseCategory,omitempty"`

	// AutoRebuildEnabled indicates whether the image has automatic CVE rebuilds enabled
	// +optional
	AutoRebuildEnabled *bool `json:"autoRebuildEnabled,omitempty"`

	// ImageAge is how old the image is (e.g. "45 days")
	// +optional
	ImageAge string `json:"imageAge,omitempty"`

	// LastCheckedAt is when the certification data was last verified against Pyxis
	// +optional
	LastCheckedAt string `json:"lastCheckedAt,omitempty"`

	// CVEIDs is the list of CVE identifiers found for this image
	// +optional
	CVEIDs []string `json:"cveIds,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=tlsreport
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.spec.port`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.sourceKind`
// +kubebuilder:printcolumn:name="Compliance",type=string,JSONPath=`.status.complianceStatus`
// +kubebuilder:printcolumn:name="Grade",type=string,JSONPath=`.status.overallCipherGrade`
// +kubebuilder:printcolumn:name="FS",type=boolean,JSONPath=`.status.forwardSecrecy`
// +kubebuilder:printcolumn:name="TLS1.3",type=boolean,JSONPath=`.status.tlsVersions.tls13`
// +kubebuilder:printcolumn:name="TLS1.2",type=boolean,JSONPath=`.status.tlsVersions.tls12`
// +kubebuilder:printcolumn:name="TLS1.0",type=boolean,JSONPath=`.status.tlsVersions.tls10`
// +kubebuilder:printcolumn:name="SSL3.0",type=boolean,JSONPath=`.status.tlsVersions.ssl30`,priority=1
// +kubebuilder:printcolumn:name="MLKEM",type=boolean,JSONPath=`.status.mlkemSupported`,priority=1
// +kubebuilder:printcolumn:name="PQC",type=string,JSONPath=`.status.pqcReadiness`
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
