package tlscheck

import "strings"

// CipherGrade represents the strength grade of a cipher suite.
type CipherGrade string

const (
	// GradeA represents AEAD ciphers with ephemeral key exchange (all TLS 1.3, GCM/ChaCha20 with ECDHE/DHE).
	GradeA CipherGrade = "A"
	// GradeB represents CBC ciphers with ephemeral key exchange (forward secrecy but no AEAD).
	GradeB CipherGrade = "B"
	// GradeC represents RSA key exchange ciphers (no forward secrecy).
	GradeC CipherGrade = "C"
	// GradeD represents weak ciphers (3DES, RC4).
	GradeD CipherGrade = "D"
	// GradeF represents NULL or export ciphers.
	GradeF CipherGrade = "F"
)

// gradeOrder defines grade ordering from best to worst for comparison.
var gradeOrder = map[CipherGrade]int{
	GradeA: 0,
	GradeB: 1,
	GradeC: 2,
	GradeD: 3,
	GradeF: 4,
}

// GradeCipherSuite returns the strength grade for a given IANA cipher suite name.
func GradeCipherSuite(name string) CipherGrade {
	// NULL or export ciphers
	if strings.Contains(name, "NULL") || strings.Contains(name, "EXPORT") {
		return GradeF
	}

	// Weak ciphers: 3DES and RC4
	if strings.Contains(name, "3DES") || strings.Contains(name, "RC4") {
		return GradeD
	}

	// TLS 1.3 ciphers are all Grade A (AEAD with ephemeral key exchange)
	if !strings.Contains(name, "_WITH_") {
		return GradeA
	}

	// Check for ephemeral key exchange (ECDHE or DHE)
	hasEphemeral := strings.HasPrefix(name, "TLS_ECDHE_") || strings.HasPrefix(name, "TLS_DHE_")

	// Check for AEAD cipher (GCM or CHACHA20_POLY1305)
	isAEAD := strings.Contains(name, "GCM") || strings.Contains(name, "CHACHA20_POLY1305")

	if hasEphemeral && isAEAD {
		return GradeA
	}
	if hasEphemeral {
		return GradeB
	}

	// RSA key exchange (no forward secrecy)
	return GradeC
}

// GradeCipherSuites returns per-cipher grades for a map of TLS version to cipher suite names.
func GradeCipherSuites(cipherSuites map[string][]string) map[string]string {
	grades := make(map[string]string)
	for _, suites := range cipherSuites {
		for _, suite := range suites {
			if _, exists := grades[suite]; !exists {
				grades[suite] = string(GradeCipherSuite(suite))
			}
		}
	}
	return grades
}

// OverallGrade returns the worst (lowest) grade across all cipher suites.
// Returns an empty string if no cipher suites are provided.
func OverallGrade(cipherSuites map[string][]string) string {
	worst := GradeA
	found := false

	for _, suites := range cipherSuites {
		for _, suite := range suites {
			found = true
			grade := GradeCipherSuite(suite)
			if gradeOrder[grade] > gradeOrder[worst] {
				worst = grade
			}
		}
	}

	if !found {
		return ""
	}
	return string(worst)
}
