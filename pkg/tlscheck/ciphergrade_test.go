package tlscheck

import (
	"crypto/tls"
	"testing"
)

func TestGradeCipherSuite(t *testing.T) {
	tests := []struct {
		name     string
		expected CipherGrade
	}{
		// Grade A: TLS 1.3 ciphers (AEAD, ephemeral key exchange)
		{"TLS_AES_128_GCM_SHA256", GradeA},
		{"TLS_AES_256_GCM_SHA384", GradeA},
		{"TLS_CHACHA20_POLY1305_SHA256", GradeA},

		// Grade A: ECDHE + AEAD
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", GradeA},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", GradeA},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", GradeA},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", GradeA},
		{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", GradeA},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", GradeA},

		// Grade B: ECDHE + CBC
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", GradeB},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", GradeB},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", GradeB},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", GradeB},
		{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", GradeB},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", GradeB},

		// Grade C: RSA key exchange (no forward secrecy)
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", GradeC},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", GradeC},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", GradeC},
		{"TLS_RSA_WITH_AES_256_CBC_SHA", GradeC},
		{"TLS_RSA_WITH_AES_128_CBC_SHA256", GradeC},

		// Grade D: Weak ciphers (3DES, RC4)
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", GradeD},
		{"TLS_RSA_WITH_RC4_128_SHA", GradeD},
		{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", GradeD},
		{"TLS_ECDHE_RSA_WITH_RC4_128_SHA", GradeD},
		{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", GradeD},

		// Grade F: NULL/export ciphers
		{"TLS_RSA_WITH_NULL_SHA", GradeF},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", GradeF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GradeCipherSuite(tt.name)
			if got != tt.expected {
				t.Errorf("GradeCipherSuite(%q) = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

func TestAllGoCipherSuitesGraded(t *testing.T) {
	allSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, suite := range allSuites {
		grade := GradeCipherSuite(suite.Name)
		if grade == "" {
			t.Errorf("cipher suite %q (0x%04x) returned empty grade", suite.Name, suite.ID)
		}
	}
}

func TestGradeCipherSuites(t *testing.T) {
	cipherSuites := map[string][]string{
		"TLS 1.3": {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA"},
	}

	grades := GradeCipherSuites(cipherSuites)

	expected := map[string]string{
		"TLS_AES_128_GCM_SHA256":                "A",
		"TLS_AES_256_GCM_SHA384":                "A",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "A",
		"TLS_RSA_WITH_AES_128_CBC_SHA":          "C",
	}

	for cipher, expectedGrade := range expected {
		if grade, ok := grades[cipher]; !ok {
			t.Errorf("missing grade for cipher %q", cipher)
		} else if grade != expectedGrade {
			t.Errorf("GradeCipherSuites[%q] = %q, want %q", cipher, grade, expectedGrade)
		}
	}
}

func TestOverallGrade(t *testing.T) {
	tests := []struct {
		name         string
		cipherSuites map[string][]string
		expected     string
	}{
		{
			name:         "empty",
			cipherSuites: map[string][]string{},
			expected:     "",
		},
		{
			name: "all grade A",
			cipherSuites: map[string][]string{
				"TLS 1.3": {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
			},
			expected: "A",
		},
		{
			name: "mixed A and B",
			cipherSuites: map[string][]string{
				"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
			},
			expected: "B",
		},
		{
			name: "mixed A and C",
			cipherSuites: map[string][]string{
				"TLS 1.3": {"TLS_AES_128_GCM_SHA256"},
				"TLS 1.2": {"TLS_RSA_WITH_AES_128_GCM_SHA256"},
			},
			expected: "C",
		},
		{
			name: "includes weak cipher",
			cipherSuites: map[string][]string{
				"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				"TLS 1.0": {"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
			},
			expected: "D",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OverallGrade(tt.cipherSuites)
			if got != tt.expected {
				t.Errorf("OverallGrade() = %q, want %q", got, tt.expected)
			}
		})
	}
}
