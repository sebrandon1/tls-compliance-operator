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

// TLS adherence modes from APIServer spec.tlsAdherence
const (
	AdherenceLegacy = "LegacyAdheringComponentsOnly"
	AdherenceStrict = "StrictAllComponents"
)

// Profile represents a resolved TLS security profile with its allowed
// ciphers and minimum TLS version.
type Profile struct {
	Type          ProfileType
	MinTLSVersion TLSVersion
	// Ciphers contains the allowed cipher suite names in OpenSSL format.
	Ciphers []string
	// Groups contains the allowed TLS key exchange group names in profile format
	// (e.g. secp256r1, X25519). Empty means groups are not checked.
	Groups []string
}

// ComplianceResult contains the result of checking an endpoint against a profile.
type ComplianceResult struct {
	ProfileType       string   `json:"profileType"`
	Compliant         bool     `json:"compliant"`
	MinTLSVersionMet  bool     `json:"minTLSVersionMet"`
	DisallowedCiphers []string `json:"disallowedCiphers,omitempty"`
	GroupsCompliant   bool     `json:"groupsCompliant"`
	DisallowedGroups  []string `json:"disallowedGroups,omitempty"`
}

// PredefinedProfiles contains the well-known OpenShift TLS security profile definitions.
// Ciphers based on Mozilla Server Side TLS v5.7, groups based on v5.8.
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
		Groups: []string{
			"X25519", "secp256r1", "secp384r1", "secp521r1",
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
		Groups: []string{
			"X25519MLKEM768", "X25519", "secp256r1", "secp384r1",
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
		Groups: []string{
			"X25519MLKEM768", "X25519", "secp256r1", "secp384r1",
		},
	},
}

// DefaultProfile returns the default TLS security profile (Intermediate).
func DefaultProfile() Profile {
	return PredefinedProfiles[ProfileTypeIntermediate]
}

// CheckCompliance checks whether an endpoint's TLS check results comply with
// the given profile. It verifies the minimum TLS version, that all negotiated
// ciphers are in the allowed list, and that negotiated curves are in the
// allowed groups list (when the profile specifies groups).
func CheckCompliance(profile *Profile, supportsTLS10, supportsTLS11, supportsTLS12, supportsTLS13 bool, cipherSuites map[string][]string, negotiatedCurves map[string]string) ComplianceResult {
	result := ComplianceResult{
		ProfileType:     string(profile.Type),
		GroupsCompliant: true,
	}

	result.MinTLSVersionMet = checkMinVersion(profile.MinTLSVersion, supportsTLS10, supportsTLS11, supportsTLS12, supportsTLS13)

	// Check ciphers: convert profile names from OpenSSL to IANA for comparison.
	allowedIANA := make(map[string]bool, len(profile.Ciphers))
	for _, c := range profile.Ciphers {
		allowedIANA[tlscheck.OpenSSLToIANA(c)] = true
	}

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

	// Check groups: convert profile names to Go CurveID.String() format for comparison.
	if len(profile.Groups) > 0 {
		allowedGoNames := make(map[string]bool, len(profile.Groups))
		for _, g := range profile.Groups {
			allowedGoNames[tlscheck.ProfileToGoCurve(g)] = true
		}

		seenCurves := make(map[string]bool)
		for _, curve := range negotiatedCurves {
			if curve == "" || seenCurves[curve] {
				continue
			}
			seenCurves[curve] = true
			if !allowedGoNames[curve] {
				result.DisallowedGroups = append(result.DisallowedGroups, tlscheck.GoCurveToProfile(curve))
				result.GroupsCompliant = false
			}
		}
	}

	result.Compliant = result.MinTLSVersionMet && len(result.DisallowedCiphers) == 0 && result.GroupsCompliant
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
