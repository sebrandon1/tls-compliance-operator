package tlscheck

import (
	"crypto/tls"
	"testing"
)

func TestIANAToOpenSSL(t *testing.T) {
	tests := []struct {
		iana    string
		openssl string
	}{
		// TLS 1.3 (names are identical)
		{"TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"},
		{"TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"},
		{"TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},

		// ECDHE+ECDSA
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"},
		{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305"},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE-ECDSA-AES128-SHA"},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE-ECDSA-AES256-SHA"},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256"},

		// ECDHE+RSA
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-CHACHA20-POLY1305"},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA"},
		{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE-RSA-AES256-SHA"},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256"},
		{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA"},

		// RSA key exchange
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256"},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384"},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA"},
		{"TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA"},
		{"TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256"},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA"},
		{"TLS_RSA_WITH_RC4_128_SHA", "RC4-SHA"},

		// Insecure ECDHE suites
		{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE-ECDSA-RC4-SHA"},
		{"TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE-RSA-RC4-SHA"},
	}

	for _, tt := range tests {
		t.Run(tt.iana, func(t *testing.T) {
			got := IANAToOpenSSL(tt.iana)
			if got != tt.openssl {
				t.Errorf("IANAToOpenSSL(%q) = %q, want %q", tt.iana, got, tt.openssl)
			}
		})
	}
}

func TestOpenSSLToIANA(t *testing.T) {
	tests := []struct {
		openssl string
		iana    string
	}{
		{"ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		{"AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{"DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{"RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA"},
		{"TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"},
		{"TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},
	}

	for _, tt := range tests {
		t.Run(tt.openssl, func(t *testing.T) {
			got := OpenSSLToIANA(tt.openssl)
			if got != tt.iana {
				t.Errorf("OpenSSLToIANA(%q) = %q, want %q", tt.openssl, got, tt.iana)
			}
		})
	}
}

func TestUnknownCipherPassthrough(t *testing.T) {
	unknown := "UNKNOWN_CIPHER_SUITE"
	if got := IANAToOpenSSL(unknown); got != unknown {
		t.Errorf("IANAToOpenSSL(%q) = %q, want passthrough", unknown, got)
	}
	if got := OpenSSLToIANA(unknown); got != unknown {
		t.Errorf("OpenSSLToIANA(%q) = %q, want passthrough", unknown, got)
	}
}

func TestBidirectionalMapping(t *testing.T) {
	for iana, openssl := range ianaToOpenSSL {
		// IANA -> OpenSSL -> IANA should round-trip
		roundTripped := OpenSSLToIANA(IANAToOpenSSL(iana))
		if roundTripped != iana {
			t.Errorf("round-trip failed for IANA %q: got %q", iana, roundTripped)
		}

		// OpenSSL -> IANA -> OpenSSL should round-trip
		roundTripped = IANAToOpenSSL(OpenSSLToIANA(openssl))
		if roundTripped != openssl {
			t.Errorf("round-trip failed for OpenSSL %q: got %q", openssl, roundTripped)
		}
	}
}

func TestAllGoCipherSuitesMapped(t *testing.T) {
	// Verify that all cipher suites known to Go's crypto/tls are in our mapping
	allSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, suite := range allSuites {
		if _, ok := ianaToOpenSSL[suite.Name]; !ok {
			t.Errorf("Go cipher suite %q (0x%04x) is not in the IANA-to-OpenSSL mapping", suite.Name, suite.ID)
		}
	}
}
