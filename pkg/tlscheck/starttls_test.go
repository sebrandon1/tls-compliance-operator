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
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

// startSTARTTLSServer starts a fake STARTTLS server for the given protocol,
// returning host, port, and a cleanup function. The server performs the
// cleartext upgrade handshake and then serves TLS using cert.
func startSTARTTLSServer(t *testing.T, proto starttlsProtocol, cert tls.Certificate) (string, int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveSTARTTLS(conn, proto, cert)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = listener.Close() }
}

func serveSTARTTLS(conn net.Conn, proto starttlsProtocol, cert tls.Certificate) {
	defer conn.Close()
	switch proto {
	case starttlsProtocolSMTP:
		serveSMTP(conn, cert)
	case starttlsProtocolIMAP:
		serveIMAP(conn, cert)
	case starttlsProtocolLDAP:
		serveLDAP(conn, cert)
	case starttlsProtocolPostgres:
		servePostgres(conn, cert)
	}
}

func serveSMTP(conn net.Conn, cert tls.Certificate) {
	fmt.Fprintf(conn, "220 test.example.com ESMTP\r\n")
	r := bufio.NewReader(conn)
	_, _ = r.ReadString('\n') // consume EHLO
	fmt.Fprintf(conn, "250-test.example.com\r\n250-STARTTLS\r\n250 OK\r\n")
	_, _ = r.ReadString('\n') // consume STARTTLS
	fmt.Fprintf(conn, "220 Go ahead\r\n")
	upgradedConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	_ = upgradedConn.Handshake()
}

func serveIMAP(conn net.Conn, cert tls.Certificate) {
	fmt.Fprintf(conn, "* OK IMAP4rev1 Service Ready\r\n")
	r := bufio.NewReader(conn)
	_, _ = r.ReadString('\n') // consume STARTTLS
	fmt.Fprintf(conn, "a001 OK Begin TLS negotiation\r\n")
	upgradedConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	_ = upgradedConn.Handshake()
}

func serveLDAP(conn net.Conn, cert tls.Certificate) {
	// Read the StartTLS ExtendedRequest (31 bytes).
	buf := make([]byte, 64)
	_, _ = conn.Read(buf)
	// Send a minimal ExtendedResponse with resultCode = success (0).
	resp := []byte{
		0x30, 0x0c, // SEQUENCE (LDAPMessage), 12 bytes
		0x02, 0x01, 0x01, // INTEGER 1 (messageID)
		0x78, 0x07, // [APPLICATION 24] (extendedResp), 7 bytes
		0x0a, 0x01, 0x00, // ENUMERATED 0 (success)
		0x04, 0x00, // OCTET STRING "" (matchedDN)
		0x04, 0x00, // OCTET STRING "" (diagnosticMessage)
	}
	_, _ = conn.Write(resp)
	upgradedConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	_ = upgradedConn.Handshake()
}

func servePostgres(conn net.Conn, cert tls.Certificate) {
	// Read the 8-byte SSLRequest.
	buf := make([]byte, 8)
	_, _ = conn.Read(buf)
	// Send 'S' to indicate SSL is supported.
	_, _ = conn.Write([]byte{'S'})
	upgradedConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	_ = upgradedConn.Handshake()
}

// startSTARTTLSRefusedServer starts a server that rejects the STARTTLS upgrade
// but speaks plaintext on the socket (simulates a non-TLS-capable server).
func startSTARTTLSRefusedServer(t *testing.T, proto starttlsProtocol) (string, int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go refuseSTARTTLS(conn, proto)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = listener.Close() }
}

func refuseSTARTTLS(conn net.Conn, proto starttlsProtocol) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	switch proto {
	case starttlsProtocolSMTP:
		fmt.Fprintf(conn, "220 test.example.com ESMTP\r\n")
		_, _ = r.ReadString('\n') // consume EHLO
		// Advertise no STARTTLS capability.
		fmt.Fprintf(conn, "250-test.example.com\r\n250 OK\r\n")
	case starttlsProtocolIMAP:
		fmt.Fprintf(conn, "* OK IMAP4rev1 Service Ready\r\n")
		_, _ = r.ReadString('\n') // consume STARTTLS
		fmt.Fprintf(conn, "a001 NO STARTTLS not supported\r\n")
	case starttlsProtocolLDAP:
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		// resultCode = unavailable (52 = 0x34): send a failure ExtendedResponse.
		resp := []byte{
			0x30, 0x0c,
			0x02, 0x01, 0x01,
			0x78, 0x07,
			0x0a, 0x01, 0x34,
			0x04, 0x00,
			0x04, 0x00,
		}
		_, _ = conn.Write(resp)
	case starttlsProtocolPostgres:
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{'N'})
	}
}

// checkerWithSTARTTLSOverride returns a TLSChecker that treats fakePort as
// speaking the given STARTTLS protocol, so CheckEndpoint exercises the full flow.
func checkerWithSTARTTLSOverride(timeout time.Duration, fakePort int, proto starttlsProtocol) *TLSChecker {
	c := NewTLSChecker(timeout)
	c.starttlsOverride = map[int]starttlsProtocol{fakePort: proto}
	return c
}

// --- Integration tests via CheckEndpoint ---

func TestCheckEndpoint_STARTTLS_SMTP(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startSTARTTLSServer(t, starttlsProtocolSMTP, cert)
	defer cleanup()

	checker := checkerWithSTARTTLSOverride(3*time.Second, port, starttlsProtocolSMTP)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FailureReason != FailureReasonNone {
		t.Errorf("want FailureReasonNone, got %q", result.FailureReason)
	}
	if !result.SupportsTLS12 && !result.SupportsTLS13 {
		t.Error("expected TLS 1.2 or 1.3 support via STARTTLS")
	}
}

func TestCheckEndpoint_STARTTLS_IMAP(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startSTARTTLSServer(t, starttlsProtocolIMAP, cert)
	defer cleanup()

	checker := checkerWithSTARTTLSOverride(3*time.Second, port, starttlsProtocolIMAP)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FailureReason != FailureReasonNone {
		t.Errorf("want FailureReasonNone, got %q", result.FailureReason)
	}
	if !result.SupportsTLS12 && !result.SupportsTLS13 {
		t.Error("expected TLS 1.2 or 1.3 support via STARTTLS")
	}
}

func TestCheckEndpoint_STARTTLS_LDAP(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startSTARTTLSServer(t, starttlsProtocolLDAP, cert)
	defer cleanup()

	checker := checkerWithSTARTTLSOverride(3*time.Second, port, starttlsProtocolLDAP)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FailureReason != FailureReasonNone {
		t.Errorf("want FailureReasonNone, got %q", result.FailureReason)
	}
	if !result.SupportsTLS12 && !result.SupportsTLS13 {
		t.Error("expected TLS 1.2 or 1.3 support via STARTTLS")
	}
}

func TestCheckEndpoint_STARTTLS_Postgres(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startSTARTTLSServer(t, starttlsProtocolPostgres, cert)
	defer cleanup()

	checker := checkerWithSTARTTLSOverride(3*time.Second, port, starttlsProtocolPostgres)
	result, err := checker.CheckEndpoint(context.Background(), host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FailureReason != FailureReasonNone {
		t.Errorf("want FailureReasonNone, got %q", result.FailureReason)
	}
	if !result.SupportsTLS12 && !result.SupportsTLS13 {
		t.Error("expected TLS 1.2 or 1.3 support via STARTTLS")
	}
}

func TestCheckEndpoint_STARTTLS_UpgradeRefused(t *testing.T) {
	tests := []struct {
		name  string
		proto starttlsProtocol
	}{
		{"smtp", starttlsProtocolSMTP},
		{"imap", starttlsProtocolIMAP},
		{"ldap", starttlsProtocolLDAP},
		{"postgres", starttlsProtocolPostgres},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, cleanup := startSTARTTLSRefusedServer(t, tt.proto)
			defer cleanup()

			checker := checkerWithSTARTTLSOverride(3*time.Second, port, tt.proto)
			result, err := checker.CheckEndpoint(context.Background(), host, port)
			if err == nil {
				t.Fatal("expected error for refused STARTTLS")
			}
			if result.FailureReason == FailureReasonNone {
				t.Error("expected non-zero failure reason for refused STARTTLS")
			}
		})
	}
}

func TestCheckEndpoint_STARTTLS_UnknownPort(t *testing.T) {
	// Server that sends binary garbage; no STARTTLS override registered.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("\x00\x01BINARY\r\n"))
			conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	result, err := checker.CheckEndpoint(context.Background(), addr.IP.String(), addr.Port)
	if err == nil {
		t.Fatal("expected error")
	}
	if result.FailureReason != FailureReasonNoTLS {
		t.Errorf("want FailureReasonNoTLS, got %q", result.FailureReason)
	}
}

func TestCheckEndpoint_STARTTLS_Timeout(t *testing.T) {
	// Silent server: accepts and does nothing.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without sending anything.
			time.Sleep(10 * time.Second)
			conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := checkerWithSTARTTLSOverride(200*time.Millisecond, addr.Port, starttlsProtocolSMTP)
	result, _ := checker.CheckEndpoint(context.Background(), addr.IP.String(), addr.Port)
	if result.FailureReason != FailureReasonTimeout {
		t.Errorf("want FailureReasonTimeout, got %q", result.FailureReason)
	}
}

// --- Unit tests for upgradeSTARTTLS per protocol ---

func TestUpgradeSTARTTLS_SMTP(t *testing.T) {
	cert, _ := generateTestCert(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serveSMTP(conn, cert)
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := upgradeSTARTTLS(conn, starttlsProtocolSMTP); err != nil {
		t.Fatalf("SMTP upgrade failed: %v", err)
	}
}

func TestUpgradeSTARTTLS_IMAP(t *testing.T) {
	cert, _ := generateTestCert(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serveIMAP(conn, cert)
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := upgradeSTARTTLS(conn, starttlsProtocolIMAP); err != nil {
		t.Fatalf("IMAP upgrade failed: %v", err)
	}
}

func TestUpgradeSTARTTLS_LDAP(t *testing.T) {
	cert, _ := generateTestCert(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serveLDAP(conn, cert)
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := upgradeSTARTTLS(conn, starttlsProtocolLDAP); err != nil {
		t.Fatalf("LDAP upgrade failed: %v", err)
	}
}

func TestUpgradeSTARTTLS_Postgres(t *testing.T) {
	cert, _ := generateTestCert(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		servePostgres(conn, cert)
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := upgradeSTARTTLS(conn, starttlsProtocolPostgres); err != nil {
		t.Fatalf("Postgres upgrade failed: %v", err)
	}
}

func TestUpgradeSTARTTLS_PostgresRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{'N'})
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := upgradeSTARTTLS(conn, starttlsProtocolPostgres); err == nil {
		t.Fatal("expected error when postgres refuses SSL")
	}
}

func TestLDAPResultSuccess(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want bool
	}{
		{
			name: "success code zero",
			buf:  []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
			want: true,
		},
		{
			name: "non-zero result code",
			buf:  []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x34, 0x04, 0x00, 0x04, 0x00},
			want: false,
		},
		{
			name: "empty",
			buf:  []byte{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ldapResultSuccess(tt.buf); got != tt.want {
				t.Errorf("ldapResultSuccess(%x) = %v, want %v", tt.buf, got, tt.want)
			}
		})
	}
}

// TestUpgradeSTARTTLS_UnknownProtocol covers the default branch in upgradeSTARTTLS.
func TestUpgradeSTARTTLS_UnknownProtocol(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// upgradeSTARTTLS returns immediately for unknown protocols — no I/O needed.
	if err := upgradeSTARTTLS(client, starttlsProtocol(99)); err == nil {
		t.Fatal("expected error for unknown protocol, got nil")
	}
}

// TestExpectSMTP220_WrongCode covers the "unexpected smtp response" branch.
func TestExpectSMTP220_WrongCode(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		fmt.Fprint(server, "550 Error\r\n")
	}()

	r := bufio.NewReader(client)
	if err := expectSMTP220(r); err == nil {
		t.Fatal("expected error when server sends wrong SMTP code, got nil")
	}
}

// TestExpectSMTP220_ShortResponse covers the len(line) < 4 branch.
func TestExpectSMTP220_ShortResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		fmt.Fprint(server, "OK\n")
	}()

	r := bufio.NewReader(client)
	if err := expectSMTP220(r); err == nil {
		t.Fatal("expected error for short SMTP response, got nil")
	}
}

// TestUpgradeSMTP_STARTTLSRejected covers the smtp: starttls response error path:
// server advertises STARTTLS but then rejects the STARTTLS command with 454.
func TestUpgradeSMTP_STARTTLSRejected(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		fmt.Fprint(conn, "220 test.example.com ESMTP\r\n")
		_, _ = r.ReadString('\n')
		fmt.Fprint(conn, "250-test.example.com\r\n250-STARTTLS\r\n250 OK\r\n")
		_, _ = r.ReadString('\n')
		fmt.Fprint(conn, "454 TLS not available\r\n")
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := upgradeSTARTTLS(conn, starttlsProtocolSMTP); err == nil {
		t.Fatal("expected error when STARTTLS command is rejected with 454, got nil")
	}
}

// TestUpgradeIMAP_BadGreeting covers the imap: unexpected greeting branch.
func TestUpgradeIMAP_BadGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "* BAD Server not ready\r\n")
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := upgradeSTARTTLS(conn, starttlsProtocolIMAP); err == nil {
		t.Fatal("expected error for unexpected IMAP greeting, got nil")
	}
}

func TestUpgradeSTARTTLS_SSLRequest(t *testing.T) {
	// Verify the Postgres SSLRequest bytes are correct:
	// length = 8, magic = 80877103 (0x04D2162F).
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8)
		n, _ := conn.Read(buf)
		received <- buf[:n]
		_, _ = conn.Write([]byte{'N'})
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = upgradeSTARTTLS(conn, starttlsProtocolPostgres)
	conn.Close()

	msg := <-received
	if len(msg) != 8 {
		t.Fatalf("expected 8-byte SSLRequest, got %d bytes", len(msg))
	}
	length := binary.BigEndian.Uint32(msg[0:4])
	magic := binary.BigEndian.Uint32(msg[4:8])
	if length != 8 {
		t.Errorf("SSLRequest length = %d, want 8", length)
	}
	if magic != 80877103 {
		t.Errorf("SSLRequest magic = %d, want 80877103", magic)
	}
}
