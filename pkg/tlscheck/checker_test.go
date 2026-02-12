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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing
func generateTestCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, parsedCert
}

// startTLSServer starts a TLS server with the given min/max TLS versions
func startTLSServer(t *testing.T, cert tls.Certificate, minVersion, maxVersion uint16) (string, int, func()) {
	t.Helper()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Complete the TLS handshake before closing
			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = listener.Close() }
}

func TestTLSChecker_CheckEndpoint_TLS12Only(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS12)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if !result.SupportsTLS12 {
		t.Error("expected TLS 1.2 to be supported")
	}
	if result.SupportsTLS10 {
		t.Error("expected TLS 1.0 to not be supported")
	}
	if result.SupportsTLS11 {
		t.Error("expected TLS 1.1 to not be supported")
	}
	if result.SupportsTLS13 {
		t.Error("expected TLS 1.3 to not be supported")
	}
	if result.Certificate == nil {
		t.Error("expected certificate info to be populated")
	}
	if result.Certificate != nil && result.Certificate.Subject == "" {
		t.Error("expected certificate subject to be populated")
	}
}

func TestTLSChecker_CheckEndpoint_TLS12And13(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if !result.SupportsTLS12 {
		t.Error("expected TLS 1.2 to be supported")
	}
	if !result.SupportsTLS13 {
		t.Error("expected TLS 1.3 to be supported")
	}
	if result.SupportsTLS10 {
		t.Error("expected TLS 1.0 to not be supported")
	}
	if result.SupportsTLS11 {
		t.Error("expected TLS 1.1 to not be supported")
	}
}

func TestTLSChecker_CheckEndpoint_Unreachable(t *testing.T) {
	checker := NewTLSChecker(500 * time.Millisecond)
	// Use a port that's unlikely to be open
	result, err := checker.CheckEndpoint(context.Background(), "127.0.0.1", 1)
	if err == nil {
		t.Error("expected error for unreachable endpoint")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
}

func TestTLSChecker_CheckEndpoint_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	checker := NewTLSChecker(2 * time.Second)
	_, err := checker.CheckEndpoint(ctx, "127.0.0.1", 443)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestTLSChecker_CipherSuites(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if len(result.CipherSuites) == 0 {
		t.Error("expected cipher suites to be populated")
	}
}

func TestRateLimitedChecker(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	defer cleanup()

	baseChecker := NewTLSChecker(2 * time.Second)
	checker := NewRateLimitedChecker(baseChecker, 100.0, 10)

	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("RateLimitedChecker.CheckEndpoint() error = %v", err)
	}
	if !result.SupportsTLS12 {
		t.Error("expected TLS 1.2 to be supported through rate limited checker")
	}
}

func TestParseCertificate(t *testing.T) {
	_, cert := generateTestCert(t)

	details := ParseCertificate(cert)
	if details.Subject == "" {
		t.Error("expected subject to be populated")
	}
	if details.Issuer == "" {
		t.Error("expected issuer to be populated")
	}
	if details.IsExpired {
		t.Error("expected certificate to not be expired")
	}
	if details.DaysUntilExpiry < 0 {
		t.Error("expected positive days until expiry")
	}
	if len(details.DNSNames) == 0 {
		t.Error("expected DNS names to be populated")
	}
}

func TestNewTLSChecker_DefaultTimeout(t *testing.T) {
	checker := NewTLSChecker(0)
	if checker.Timeout != DefaultTimeout {
		t.Errorf("expected default timeout %v, got %v", DefaultTimeout, checker.Timeout)
	}
}

func TestTLSChecker_CertificateExpiry(t *testing.T) {
	cert, parsedCert := generateTestCert(t)
	_ = parsedCert

	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS12)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if result.Certificate == nil {
		t.Fatal("expected certificate info to be populated")
	}

	if result.Certificate.IsExpired {
		t.Error("expected test certificate to not be expired")
	}

	// Test certificate is valid for 24 hours
	if result.Certificate.DaysUntilExpiry > 1 {
		t.Errorf("expected days until expiry to be 0 or 1, got %d", result.Certificate.DaysUntilExpiry)
	}
}

