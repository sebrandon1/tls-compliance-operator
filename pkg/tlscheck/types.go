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

package tlscheck

import (
	"crypto/x509"
	"time"
)

// TLSCheckResult contains the results of a TLS endpoint check
type TLSCheckResult struct {
	// TLS version support
	SupportsTLS10 bool
	SupportsTLS11 bool
	SupportsTLS12 bool
	SupportsTLS13 bool

	// Cipher suites per TLS version
	CipherSuites map[string][]string

	// Certificate details (from the first successful connection)
	Certificate *CertificateDetails

	// Check metadata
	CheckDuration time.Duration
}

// CertificateDetails contains parsed certificate information
type CertificateDetails struct {
	Issuer          string
	Subject         string
	NotBefore       time.Time
	NotAfter        time.Time
	DNSNames        []string
	IsExpired       bool
	DaysUntilExpiry int
}

// ParseCertificate extracts CertificateDetails from an x509 certificate
func ParseCertificate(cert *x509.Certificate) *CertificateDetails {
	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	return &CertificateDetails{
		Issuer:          cert.Issuer.String(),
		Subject:         cert.Subject.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DNSNames:        cert.DNSNames,
		IsExpired:       now.After(cert.NotAfter),
		DaysUntilExpiry: daysUntilExpiry,
	}
}
