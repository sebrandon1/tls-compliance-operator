package tlsprofile

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCheckCompliance_IntermediateProfile_Compliant(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]

	ciphers := map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}

	result := CheckCompliance(profile, false, false, true, true, ciphers, nil)

	if !result.Compliant {
		t.Errorf("expected compliant, got non-compliant: disallowed=%v, minVersionMet=%v",
			result.DisallowedCiphers, result.MinTLSVersionMet)
	}
	if !result.MinTLSVersionMet {
		t.Error("expected MinTLSVersionMet to be true")
	}
	if len(result.DisallowedCiphers) != 0 {
		t.Errorf("expected no disallowed ciphers, got %v", result.DisallowedCiphers)
	}
}

func TestCheckCompliance_IntermediateProfile_TLSVersionViolation(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]

	ciphers := map[string][]string{
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}

	result := CheckCompliance(profile, true, false, true, false, ciphers, nil)

	if result.Compliant {
		t.Error("expected non-compliant due to TLS 1.0 support")
	}
	if result.MinTLSVersionMet {
		t.Error("expected MinTLSVersionMet to be false")
	}
}

func TestCheckCompliance_IntermediateProfile_CipherViolation(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]

	ciphers := map[string][]string{
		"TLS 1.2": {
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", // Not in Intermediate
		},
	}

	result := CheckCompliance(profile, false, false, true, false, ciphers, nil)

	if result.Compliant {
		t.Error("expected non-compliant due to disallowed cipher")
	}
	if !result.MinTLSVersionMet {
		t.Error("expected MinTLSVersionMet to be true")
	}
	if len(result.DisallowedCiphers) != 1 || result.DisallowedCiphers[0] != "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" {
		t.Errorf("expected disallowed cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, got %v", result.DisallowedCiphers)
	}
}

func TestCheckCompliance_OldProfile_Compliant(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeOld]

	ciphers := map[string][]string{
		"TLS 1.0": {"TLS_RSA_WITH_AES_128_CBC_SHA"},
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}

	result := CheckCompliance(profile, true, false, true, false, ciphers, nil)

	if !result.Compliant {
		t.Errorf("expected compliant with Old profile, got: disallowed=%v, minVersionMet=%v",
			result.DisallowedCiphers, result.MinTLSVersionMet)
	}
}

func TestCheckCompliance_ModernProfile_Compliant(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeModern]

	ciphers := map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},
	}

	result := CheckCompliance(profile, false, false, false, true, ciphers, nil)

	if !result.Compliant {
		t.Errorf("expected compliant with Modern profile, got: disallowed=%v", result.DisallowedCiphers)
	}
}

func TestCheckCompliance_ModernProfile_TLS12NotAllowed(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeModern]

	ciphers := map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256"},
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}

	result := CheckCompliance(profile, false, false, true, true, ciphers, nil)

	if result.Compliant {
		t.Error("expected non-compliant: Modern profile should reject TLS 1.2 support")
	}
	if result.MinTLSVersionMet {
		t.Error("expected MinTLSVersionMet to be false")
	}
}

func TestCheckCompliance_EmptyCiphers(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]

	result := CheckCompliance(profile, false, false, true, true, map[string][]string{}, nil)

	if !result.Compliant {
		t.Error("expected compliant with empty cipher suites")
	}
}

func TestCheckCompliance_CustomProfile(t *testing.T) {
	profile := Profile{
		Type:          ProfileTypeCustom,
		MinTLSVersion: VersionTLS12,
		Ciphers: []string{
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES256-GCM-SHA384",
		},
	}

	ciphers := map[string][]string{
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}

	result := CheckCompliance(profile, false, false, true, false, ciphers, nil)

	if !result.Compliant {
		t.Errorf("expected compliant with custom profile, got: disallowed=%v", result.DisallowedCiphers)
	}
	if result.ProfileType != "Custom" {
		t.Errorf("expected profile type Custom, got %s", result.ProfileType)
	}
}

func TestCheckCompliance_DuplicateCiphersCounted(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]

	ciphers := map[string][]string{
		"TLS 1.2": {"TLS_RSA_WITH_AES_128_CBC_SHA"},
		"TLS 1.0": {"TLS_RSA_WITH_AES_128_CBC_SHA"},
	}

	result := CheckCompliance(profile, true, false, true, false, ciphers, nil)

	if result.Compliant {
		t.Error("expected non-compliant")
	}
	disallowedCount := 0
	for _, c := range result.DisallowedCiphers {
		if c == "TLS_RSA_WITH_AES_128_CBC_SHA" {
			disallowedCount++
		}
	}
	if disallowedCount != 1 {
		t.Errorf("expected disallowed cipher listed once, got %d times", disallowedCount)
	}
}

func TestCheckMinVersion(t *testing.T) {
	tests := []struct {
		name       string
		minVersion TLSVersion
		tls10      bool
		tls11      bool
		tls12      bool
		tls13      bool
		expected   bool
	}{
		{"TLS10 min, no support", VersionTLS10, false, false, false, false, true},
		{"TLS10 min, TLS10 supported", VersionTLS10, true, false, false, false, true},
		{"TLS12 min, TLS10 supported", VersionTLS12, true, false, true, false, false},
		{"TLS12 min, TLS11 supported", VersionTLS12, false, true, true, false, false},
		{"TLS12 min, only TLS12", VersionTLS12, false, false, true, false, true},
		{"TLS12 min, TLS12 and TLS13", VersionTLS12, false, false, true, true, true},
		{"TLS13 min, TLS12 supported", VersionTLS13, false, false, true, true, false},
		{"TLS13 min, only TLS13", VersionTLS13, false, false, false, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkMinVersion(tt.minVersion, tt.tls10, tt.tls11, tt.tls12, tt.tls13)
			if got != tt.expected {
				t.Errorf("checkMinVersion(%s, %v,%v,%v,%v) = %v, want %v",
					tt.minVersion, tt.tls10, tt.tls11, tt.tls12, tt.tls13, got, tt.expected)
			}
		})
	}
}

func TestDefaultProfile(t *testing.T) {
	p := DefaultProfile()
	if p.Type != ProfileTypeIntermediate {
		t.Errorf("expected Intermediate, got %s", p.Type)
	}
	if p.MinTLSVersion != VersionTLS12 {
		t.Errorf("expected VersionTLS12, got %s", p.MinTLSVersion)
	}
}

func TestExtractProfileFromUnstructured(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]any
		expected ProfileType
	}{
		{
			name: "intermediate",
			data: map[string]any{
				"spec": map[string]any{
					"tlsSecurityProfile": map[string]any{
						"type": "Intermediate",
					},
				},
			},
			expected: ProfileTypeIntermediate,
		},
		{
			name: "old",
			data: map[string]any{
				"spec": map[string]any{
					"tlsSecurityProfile": map[string]any{
						"type": "Old",
					},
				},
			},
			expected: ProfileTypeOld,
		},
		{
			name: "modern",
			data: map[string]any{
				"spec": map[string]any{
					"tlsSecurityProfile": map[string]any{
						"type": "Modern",
					},
				},
			},
			expected: ProfileTypeModern,
		},
		{
			name: "default when no profile",
			data: map[string]any{
				"spec": map[string]any{},
			},
			expected: ProfileTypeIntermediate,
		},
		{
			name: "custom profile",
			data: map[string]any{
				"spec": map[string]any{
					"tlsSecurityProfile": map[string]any{
						"type": "Custom",
						"custom": map[string]any{
							"minTLSVersion": "VersionTLS13",
							"ciphers": []any{
								"TLS_AES_128_GCM_SHA256",
								"TLS_AES_256_GCM_SHA384",
							},
						},
					},
				},
			},
			expected: ProfileTypeCustom,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: tt.data}
			profile, err := extractProfileFromUnstructured(obj)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if profile.Type != tt.expected {
				t.Errorf("expected type %s, got %s", tt.expected, profile.Type)
			}
			if tt.expected == ProfileTypeCustom {
				if profile.MinTLSVersion != VersionTLS13 {
					t.Errorf("expected minTLSVersion VersionTLS13, got %s", profile.MinTLSVersion)
				}
				if len(profile.Ciphers) != 2 {
					t.Errorf("expected 2 ciphers, got %d", len(profile.Ciphers))
				}
			}
		})
	}
}

func TestExtractAdherence(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]any
		expected string
	}{
		{
			name: "StrictAllComponents",
			data: map[string]any{
				"spec": map[string]any{
					"tlsAdherence": "StrictAllComponents",
				},
			},
			expected: AdherenceStrict,
		},
		{
			name: "LegacyAdheringComponentsOnly",
			data: map[string]any{
				"spec": map[string]any{
					"tlsAdherence": "LegacyAdheringComponentsOnly",
				},
			},
			expected: AdherenceLegacy,
		},
		{
			name:     "field absent",
			data:     map[string]any{"spec": map[string]any{}},
			expected: "",
		},
		{
			name:     "no spec",
			data:     map[string]any{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: tt.data}
			got := extractAdherence(obj)
			if got != tt.expected {
				t.Errorf("extractAdherence() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCheckCompliance_GroupsAllowed(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]
	ciphers := map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256"},
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}
	curves := map[string]string{
		"TLS 1.3": "X25519",
		"TLS 1.2": "CurveP256",
	}

	result := CheckCompliance(profile, false, false, true, true, ciphers, curves)
	if !result.GroupsCompliant {
		t.Error("expected GroupsCompliant to be true for allowed curves")
	}
	if len(result.DisallowedGroups) > 0 {
		t.Errorf("expected no disallowed groups, got %v", result.DisallowedGroups)
	}
	if !result.Compliant {
		t.Error("expected overall compliance to be true")
	}
}

func TestCheckCompliance_GroupsDisallowed(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]
	ciphers := map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256"},
	}
	curves := map[string]string{
		"TLS 1.3": "CurveP521",
	}

	result := CheckCompliance(profile, false, false, true, true, ciphers, curves)
	if result.GroupsCompliant {
		t.Error("expected GroupsCompliant to be false for disallowed curve")
	}
	if len(result.DisallowedGroups) != 1 || result.DisallowedGroups[0] != "secp521r1" {
		t.Errorf("expected DisallowedGroups=[secp521r1], got %v", result.DisallowedGroups)
	}
	if result.Compliant {
		t.Error("expected overall compliance to be false when groups are non-compliant")
	}
}

func TestCheckCompliance_EmptyProfileGroups(t *testing.T) {
	profile := Profile{
		Type:          ProfileTypeCustom,
		MinTLSVersion: VersionTLS12,
		Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
	}
	curves := map[string]string{
		"TLS 1.3": "CurveP521",
	}

	result := CheckCompliance(profile, false, false, true, true, map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256"},
	}, curves)
	if !result.GroupsCompliant {
		t.Error("expected GroupsCompliant true when profile has no groups defined")
	}
}

func TestCheckCompliance_GroupsAndCiphersMixed(t *testing.T) {
	profile := PredefinedProfiles[ProfileTypeIntermediate]
	ciphers := map[string][]string{
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}
	curves := map[string]string{
		"TLS 1.2": "CurveP521",
	}

	result := CheckCompliance(profile, false, false, true, false, ciphers, curves)
	if result.Compliant {
		t.Error("expected non-compliant when groups fail even if ciphers pass")
	}
	if result.GroupsCompliant {
		t.Error("expected GroupsCompliant false")
	}
	if len(result.DisallowedCiphers) > 0 {
		t.Error("expected no disallowed ciphers")
	}
}

func TestExtractCustomProfile_WithGroups(t *testing.T) {
	data := map[string]any{
		"spec": map[string]any{
			"tlsSecurityProfile": map[string]any{
				"type": "Custom",
				"custom": map[string]any{
					"minTLSVersion": "VersionTLS13",
					"ciphers": []any{
						"TLS_AES_128_GCM_SHA256",
					},
					"groups": []any{
						"X25519", "secp256r1",
					},
				},
			},
		},
	}

	obj := &unstructured.Unstructured{Object: data}
	profile, err := extractProfileFromUnstructured(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profile.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(profile.Groups))
	}
	if profile.Groups[0] != "X25519" || profile.Groups[1] != "secp256r1" {
		t.Errorf("unexpected groups: %v", profile.Groups)
	}
}
