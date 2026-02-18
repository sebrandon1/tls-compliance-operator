package tlsprofile

import (
	"github.com/sebrandon1/tls-compliance-operator/pkg/tlscheck"
)

// ProfileType represents the type of TLS security profile.
type ProfileType string

const (
	ProfileTypeOld          ProfileType = "Old"
	ProfileTypeIntermediate ProfileType = "Intermediate"
	ProfileTypeModern       ProfileType = "Modern"
	ProfileTypeCustom       ProfileType = "Custom"
)

// TLSVersion represents a TLS protocol version as used in OpenShift configs.
type TLSVersion string

const (
	VersionTLS10 TLSVersion = "VersionTLS10"
	VersionTLS11 TLSVersion = "VersionTLS11"
	VersionTLS12 TLSVersion = "VersionTLS12"
	VersionTLS13 TLSVersion = "VersionTLS13"
)

// tlsVersionOrder maps TLS versions to their ordering for comparison.
var tlsVersionOrder = map[TLSVersion]int{
	VersionTLS10: 0,
	VersionTLS11: 1,
	VersionTLS12: 2,
	VersionTLS13: 3,
}

// Component identifies which OpenShift component owns a TLS profile.
type Component string

const (
	ComponentAPIServer         Component = "APIServer"
	ComponentIngressController Component = "IngressController"
	ComponentKubeletConfig     Component = "KubeletConfig"
)

// Profile represents a resolved TLS security profile with its allowed
// ciphers and minimum TLS version.
type Profile struct {
	Type          ProfileType
	MinTLSVersion TLSVersion
	// Ciphers contains the allowed cipher suite names in OpenSSL format.
	Ciphers []string
}

// ComplianceResult contains the result of checking an endpoint against a profile.
type ComplianceResult struct {
	ProfileType       string   `json:"profileType"`
	Compliant         bool     `json:"compliant"`
	MinTLSVersionMet  bool     `json:"minTLSVersionMet"`
	DisallowedCiphers []string `json:"disallowedCiphers,omitempty"`
}

// PredefinedProfiles contains the well-known OpenShift TLS security profile definitions.
// Based on Mozilla Server Side TLS configuration guidelines, version 5.7.
var PredefinedProfiles = map[ProfileType]Profile{
	ProfileTypeOld: {
		Type:          ProfileTypeOld,
		MinTLSVersion: VersionTLS10,
		Ciphers: []string{
			// TLS 1.3
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			// ECDHE+ECDSA
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			// ECDHE+RSA
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-RSA-CHACHA20-POLY1305",
			// DHE+RSA
			"DHE-RSA-AES128-GCM-SHA256",
			"DHE-RSA-AES256-GCM-SHA384",
			"DHE-RSA-CHACHA20-POLY1305",
			// CBC suites
			"ECDHE-ECDSA-AES128-SHA256",
			"ECDHE-RSA-AES128-SHA256",
			"ECDHE-ECDSA-AES128-SHA",
			"ECDHE-RSA-AES128-SHA",
			"ECDHE-ECDSA-AES256-SHA",
			"ECDHE-RSA-AES256-SHA",
			// RSA
			"AES128-GCM-SHA256",
			"AES256-GCM-SHA384",
			"AES128-SHA256",
			"AES128-SHA",
			"AES256-SHA",
			"DES-CBC3-SHA",
		},
	},
	ProfileTypeIntermediate: {
		Type:          ProfileTypeIntermediate,
		MinTLSVersion: VersionTLS12,
		Ciphers: []string{
			// TLS 1.3
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			// TLS 1.2 ECDHE+AEAD only
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
		},
	},
	ProfileTypeModern: {
		Type:          ProfileTypeModern,
		MinTLSVersion: VersionTLS13,
		Ciphers: []string{
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
		},
	},
}

// DefaultProfile returns the default TLS security profile (Intermediate).
func DefaultProfile() Profile {
	return PredefinedProfiles[ProfileTypeIntermediate]
}

// CheckCompliance checks whether an endpoint's TLS check results comply with
// the given profile. It verifies both the minimum TLS version requirement
// and that all negotiated ciphers are in the profile's allowed list.
func CheckCompliance(profile Profile, supportsTLS10, supportsTLS11, supportsTLS12, supportsTLS13 bool, cipherSuites map[string][]string) ComplianceResult {
	result := ComplianceResult{
		ProfileType: string(profile.Type),
	}

	// Check minimum TLS version compliance.
	// The endpoint must NOT support any TLS version below the profile's minimum.
	result.MinTLSVersionMet = checkMinVersion(profile.MinTLSVersion, supportsTLS10, supportsTLS11, supportsTLS12, supportsTLS13)

	// Build a set of allowed ciphers in IANA format for comparison.
	allowedIANA := make(map[string]bool, len(profile.Ciphers))
	for _, c := range profile.Ciphers {
		// Convert OpenSSL name to IANA, since endpoint results use IANA names.
		allowedIANA[tlscheck.OpenSSLToIANA(c)] = true
	}

	// Check each negotiated cipher against the allowed set.
	seen := make(map[string]bool)
	for _, suites := range cipherSuites {
		for _, suite := range suites {
			if seen[suite] {
				continue
			}
			seen[suite] = true
			if !allowedIANA[suite] {
				result.DisallowedCiphers = append(result.DisallowedCiphers, suite)
			}
		}
	}

	result.Compliant = result.MinTLSVersionMet && len(result.DisallowedCiphers) == 0
	return result
}

// checkMinVersion returns true if the endpoint does not support any TLS version
// below the required minimum.
func checkMinVersion(minVersion TLSVersion, tls10, tls11, tls12, tls13 bool) bool {
	minOrder, ok := tlsVersionOrder[minVersion]
	if !ok {
		return false
	}

	// Check if any version below the minimum is supported
	versions := []struct {
		order     int
		supported bool
	}{
		{tlsVersionOrder[VersionTLS10], tls10},
		{tlsVersionOrder[VersionTLS11], tls11},
		{tlsVersionOrder[VersionTLS12], tls12},
		{tlsVersionOrder[VersionTLS13], tls13},
	}

	for _, v := range versions {
		if v.supported && v.order < minOrder {
			return false
		}
	}

	return true
}
