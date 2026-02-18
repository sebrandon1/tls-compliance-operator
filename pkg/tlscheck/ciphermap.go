package tlscheck

// ianaToOpenSSL maps IANA (Go crypto/tls) cipher suite names to OpenSSL names.
// This covers all cipher suites defined in Go's crypto/tls package.
var ianaToOpenSSL = map[string]string{
	// TLS 1.3 cipher suites (names are identical in IANA and OpenSSL)
	"TLS_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
	"TLS_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",
	"TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",

	// ECDHE+ECDSA cipher suites
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       "ECDHE-ECDSA-AES128-GCM-SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       "ECDHE-ECDSA-AES256-GCM-SHA384",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          "ECDHE-ECDSA-AES128-SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          "ECDHE-ECDSA-AES256-SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       "ECDHE-ECDSA-AES128-SHA256",
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              "ECDHE-ECDSA-RC4-SHA",

	// ECDHE+RSA cipher suites
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       "ECDHE-RSA-AES128-GCM-SHA256",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       "ECDHE-RSA-AES256-GCM-SHA384",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":          "ECDHE-RSA-AES128-SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":          "ECDHE-RSA-AES256-SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":       "ECDHE-RSA-AES128-SHA256",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":         "ECDHE-RSA-DES-CBC3-SHA",
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":              "ECDHE-RSA-RC4-SHA",

	// RSA key exchange cipher suites
	"TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
	"TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
	"TLS_RSA_WITH_AES_128_CBC_SHA":    "AES128-SHA",
	"TLS_RSA_WITH_AES_256_CBC_SHA":    "AES256-SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":   "DES-CBC3-SHA",
	"TLS_RSA_WITH_RC4_128_SHA":        "RC4-SHA",
}

// opensslToIANA is the reverse mapping from OpenSSL names to IANA names.
var opensslToIANA map[string]string

func init() {
	opensslToIANA = make(map[string]string, len(ianaToOpenSSL))
	for iana, openssl := range ianaToOpenSSL {
		opensslToIANA[openssl] = iana
	}
}

// IANAToOpenSSL converts an IANA cipher suite name to its OpenSSL equivalent.
// Returns the original name if no mapping is found.
func IANAToOpenSSL(name string) string {
	if mapped, ok := ianaToOpenSSL[name]; ok {
		return mapped
	}
	return name
}

// OpenSSLToIANA converts an OpenSSL cipher suite name to its IANA equivalent.
// Returns the original name if no mapping is found.
func OpenSSLToIANA(name string) string {
	if mapped, ok := opensslToIANA[name]; ok {
		return mapped
	}
	return name
}
