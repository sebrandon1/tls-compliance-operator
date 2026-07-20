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
	"errors"
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
	return startTLSServerWithCurves(t, cert, minVersion, maxVersion, nil)
}

// startTLSServerWithCurves starts a TLS server with explicit curve preferences
func startTLSServerWithCurves(t *testing.T, cert tls.Certificate, minVersion, maxVersion uint16, curves []tls.CurveID) (string, int, func()) {
	t.Helper()

	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       minVersion,
		MaxVersion:       maxVersion,
		CurvePreferences: curves,
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
	if len(result.NegotiatedCurves) == 0 {
		t.Error("expected negotiated curves to be populated")
	}
}

func TestTLSChecker_CheckEndpoint_Closed(t *testing.T) {
	checker := NewTLSChecker(500 * time.Millisecond)
	// Use a port that's not listening — should get connection refused (Closed)
	result, err := checker.CheckEndpoint(context.Background(), "127.0.0.1", 1)
	if err == nil {
		t.Error("expected error for closed endpoint")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.FailureReason != FailureReasonClosed {
		t.Errorf("expected FailureReason=%q, got %q", FailureReasonClosed, result.FailureReason)
	}
}

func TestTLSChecker_CheckEndpoint_PlaintextHTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start plain TCP listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), addr.IP.String(), addr.Port)
	if err == nil {
		t.Error("expected error for plaintext HTTP endpoint")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.FailureReason != FailureReasonPlaintextHTTP {
		t.Errorf("expected FailureReason=%q, got %q", FailureReasonPlaintextHTTP, result.FailureReason)
	}
}

func TestTLSChecker_CheckEndpoint_NoTLS_NonHTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start plain TCP listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("\x00\x01\x02BINARY PROTOCOL\r\n"))
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), addr.IP.String(), addr.Port)
	if err == nil {
		t.Error("expected error for non-TLS endpoint")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.FailureReason != FailureReasonNoTLS {
		t.Errorf("expected FailureReason=%q, got %q", FailureReasonNoTLS, result.FailureReason)
	}
}

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name     string
		errors   []error
		expected FailureReason
	}{
		{
			name:     "no errors",
			errors:   nil,
			expected: FailureReasonUnreachable,
		},
		{
			name:     "connection refused - Closed",
			errors:   []error{errors.New("dial tcp 10.0.0.1:443: connect: connection refused")},
			expected: FailureReasonClosed,
		},
		{
			name:     "i/o timeout - Timeout",
			errors:   []error{errors.New("dial tcp 10.0.0.1:443: i/o timeout")},
			expected: FailureReasonTimeout,
		},
		{
			name:     "deadline exceeded - Timeout",
			errors:   []error{errors.New("dial tcp 10.0.0.1:443: deadline exceeded")},
			expected: FailureReasonTimeout,
		},
		{
			name:     "not TLS",
			errors:   []error{errors.New("tls: first record does not look like a TLS handshake")},
			expected: FailureReasonNoTLS,
		},
		{
			name:     "oversized record",
			errors:   []error{errors.New("tls: oversized record received with length 22")},
			expected: FailureReasonNoTLS,
		},
		{
			name:     "certificate required",
			errors:   []error{errors.New("remote error: tls: certificate required")},
			expected: FailureReasonMutualTLSRequired,
		},
		{
			name:     "bad certificate",
			errors:   []error{errors.New("remote error: tls: bad certificate")},
			expected: FailureReasonMutualTLSRequired,
		},
		{
			name: "mTLS takes priority over NoTLS",
			errors: []error{
				errors.New("tls: first record does not look like a TLS handshake"),
				errors.New("remote error: tls: certificate required"),
			},
			expected: FailureReasonMutualTLSRequired,
		},
		{
			name: "mTLS takes priority over Closed",
			errors: []error{
				errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
				errors.New("remote error: tls: certificate required"),
			},
			expected: FailureReasonMutualTLSRequired,
		},
		{
			name: "NoTLS takes priority over Closed",
			errors: []error{
				errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
				errors.New("tls: first record does not look like a TLS handshake"),
			},
			expected: FailureReasonNoTLS,
		},
		{
			name: "Closed takes priority over Timeout",
			errors: []error{
				errors.New("dial tcp 10.0.0.1:443: i/o timeout"),
				errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
			},
			expected: FailureReasonClosed,
		},
		{
			name:     "unknown error falls through to Unreachable",
			errors:   []error{errors.New("some unknown network error")},
			expected: FailureReasonUnreachable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyFailure(tt.errors)
			if got != tt.expected {
				t.Errorf("classifyFailure() = %q, want %q", got, tt.expected)
			}
		})
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

	details := ParseCertificate(cert, "localhost")
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
	if details.PublicKeyAlgorithm == "" {
		t.Error("expected public key algorithm to be populated")
	}
	if details.PublicKeyBits <= 0 {
		t.Errorf("expected positive public key bits, got %d", details.PublicKeyBits)
	}
	if details.SignatureAlgorithm == "" {
		t.Error("expected signature algorithm to be populated")
	}
}

func TestParseCertificate_KubernetesSuffixMatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "api.openshift-apiserver.svc",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			"api.openshift-apiserver.svc",
			"api.openshift-apiserver.svc.cluster.local",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"exact .svc match", "api.openshift-apiserver.svc", true},
		{"exact .svc.cluster.local match", "api.openshift-apiserver.svc.cluster.local", true},
		{"short name with suffix fallback", "api.openshift-apiserver", true},
		{"unrelated hostname", "other-service.default", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details := ParseCertificate(parsedCert, tt.hostname)
			if details.HostnameMatch != tt.want {
				t.Errorf("ParseCertificate(%q).HostnameMatch = %v, want %v", tt.hostname, details.HostnameMatch, tt.want)
			}
		})
	}
}

func TestTLSChecker_ProbeMLKEM_Supported(t *testing.T) {
	cert, _ := generateTestCert(t)
	// Default CurvePreferences in Go 1.24+ include X25519MLKEM768
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS13, tls.VersionTLS13)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if !result.SupportsTLS13 {
		t.Fatal("expected TLS 1.3 to be supported")
	}
	if !result.MLKEMSupported {
		t.Error("expected MLKEMSupported to be true (server uses Go defaults which include X25519MLKEM768)")
	}
}

func TestTLSChecker_ProbeMLKEM_NotSupported(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServerWithCurves(t, cert, tls.VersionTLS13, tls.VersionTLS13,
		[]tls.CurveID{tls.X25519, tls.CurveP256})
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if !result.SupportsTLS13 {
		t.Fatal("expected TLS 1.3 to be supported")
	}
	if result.MLKEMSupported {
		t.Error("expected MLKEMSupported to be false (server only allows classical curves)")
	}
}

func TestTLSChecker_ProbeMLKEM_SecP256r1Only(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServerWithCurves(t, cert, tls.VersionTLS13, tls.VersionTLS13,
		[]tls.CurveID{tls.SecP256r1MLKEM768, tls.CurveP256})
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if !result.SupportsTLS13 {
		t.Fatal("expected TLS 1.3 to be supported")
	}
	if !result.MLKEMSupported {
		t.Error("expected MLKEMSupported to be true (server supports SecP256r1MLKEM768)")
	}
}

func TestTLSChecker_ProbeMLKEM_SecP384r1Only(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServerWithCurves(t, cert, tls.VersionTLS13, tls.VersionTLS13,
		[]tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP384})
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if !result.SupportsTLS13 {
		t.Fatal("expected TLS 1.3 to be supported")
	}
	if !result.MLKEMSupported {
		t.Error("expected MLKEMSupported to be true (server supports SecP384r1MLKEM1024)")
	}
}

func TestTLSChecker_ProbeMLKEM_TLS12Only(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS12)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}

	if result.MLKEMSupported {
		t.Error("expected MLKEMSupported to be false (TLS 1.2 only, probe should be skipped)")
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

func generateCACert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, parsed
}

func TestTLSChecker_ClientCert_mTLSEndpoint(t *testing.T) {
	caCert, caParsed := generateCACert(t)

	caPool := x509.NewCertPool()
	caPool.AddCert(caParsed)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{caCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start mTLS listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)

	// Without client cert — should fail (the exact classification depends
	// on the TLS alert the server sends; we just verify it fails)
	checker := NewTLSChecker(2 * time.Second)
	_, err = checker.CheckEndpoint(context.Background(), addr.IP.String(), addr.Port)
	if err == nil {
		t.Fatal("expected error without client cert")
	}

	// With client cert — should succeed and report full TLS details
	checkerWithCert := NewTLSChecker(2 * time.Second)
	checkerWithCert.ClientCert = &caCert
	result, err := checkerWithCert.CheckEndpoint(context.Background(), addr.IP.String(), addr.Port)
	if err != nil {
		t.Fatalf("expected success with client cert, got error: %v", err)
	}
	if !result.SupportsTLS12 {
		t.Error("expected TLS 1.2 to be supported with client cert")
	}
	if result.Certificate == nil {
		t.Error("expected server certificate info to be populated")
	}
	if len(result.CipherSuites) == 0 {
		t.Error("expected cipher suites to be populated with client cert")
	}
}

func startTLSServerWithCipherSuites(t *testing.T, cert tls.Certificate, version uint16, cipherSuites []uint16) (string, int, func()) {
	t.Helper()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
		CipherSuites: cipherSuites,
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
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = listener.Close() }
}

func TestTLSChecker_EnumerateCiphers_MultipleSuites(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServerWithCipherSuites(t, cert, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	})
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}
	suites := result.CipherSuites["TLS 1.2"]
	if len(suites) < 2 {
		t.Errorf("expected at least 2 cipher suites, got %d: %v", len(suites), suites)
	}
}

func TestTLSChecker_EnumerateCiphers_Disabled(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServerWithCipherSuites(t, cert, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	})
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	checker.EnumerateCiphers = false
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}
	suites := result.CipherSuites["TLS 1.2"]
	if len(suites) != 1 {
		t.Errorf("expected 1 cipher suite with enumeration disabled, got %d: %v", len(suites), suites)
	}
}

func TestTLSChecker_ParallelProbes_ReducesLatency(t *testing.T) {
	timeout := 500 * time.Millisecond
	checker := NewTLSChecker(timeout)

	start := time.Now()
	// Port 1 is connection-refused (fast fail), but all probes run concurrently
	_, _ = checker.CheckEndpoint(context.Background(), "127.0.0.1", 1)
	elapsed := time.Since(start)

	// With sequential probes: 5 × timeout = 2.5s minimum
	// With parallel probes: ~1× timeout = 500ms
	// Allow 2× timeout as generous upper bound
	maxExpected := 2 * timeout
	if elapsed > maxExpected {
		t.Errorf("parallel probes took %v, expected less than %v (sequential would be ~%v)",
			elapsed, maxExpected, 5*timeout)
	}
}
