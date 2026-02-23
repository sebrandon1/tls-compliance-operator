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

// generateBenchCert creates a self-signed certificate for benchmarking.
// Uses testing.B.Helper but does not call b.Fatal to allow reuse.
func generateBenchCert(b *testing.B) (tls.Certificate, *x509.Certificate) {
	b.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Bench Org"},
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
		b.Fatalf("failed to create certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, parsedCert
}

// startBenchTLSServer starts a TLS server for benchmarks
func startBenchTLSServer(b *testing.B, cert tls.Certificate, minVersion, maxVersion uint16) (string, int, func()) {
	b.Helper()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		b.Fatalf("failed to start TLS listener: %v", err)
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

func BenchmarkCheckEndpoint(b *testing.B) {
	cert, _ := generateBenchCert(b)
	host, port, cleanup := startBenchTLSServer(b, cert, tls.VersionTLS12, tls.VersionTLS13)
	defer cleanup()

	checker := NewTLSChecker(5 * time.Second)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_, _ = checker.CheckEndpoint(ctx, host, port)
	}
}

func BenchmarkParseCertificate(b *testing.B) {
	_, cert := generateBenchCert(b)

	b.ResetTimer()
	for b.Loop() {
		_ = ParseCertificate(cert)
	}
}

func BenchmarkClassifyFailure(b *testing.B) {
	errs := []error{
		errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
		errors.New("tls: first record does not look like a TLS handshake"),
		errors.New("remote error: tls: certificate required"),
		errors.New("dial tcp 10.0.0.1:443: i/o timeout"),
	}

	b.ResetTimer()
	for b.Loop() {
		_ = classifyFailure(errs)
	}
}
