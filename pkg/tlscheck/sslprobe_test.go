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
	"net"
	"testing"
	"time"
)

func TestBuildSSL30ClientHello(t *testing.T) {
	hello := buildSSL30ClientHello()

	// Must start with TLS record header
	if hello[0] != recordTypeHandshake {
		t.Errorf("record type = %d, want %d (handshake)", hello[0], recordTypeHandshake)
	}
	if hello[1] != sslVersionSSL30Major || hello[2] != sslVersionSSL30Minor {
		t.Errorf("record version = %d.%d, want 3.0", hello[1], hello[2])
	}

	// Handshake type should be ClientHello
	if hello[5] != handshakeTypeClientHello {
		t.Errorf("handshake type = %d, want %d (ClientHello)", hello[5], handshakeTypeClientHello)
	}
}

func TestProbeSSL30_NoServer(t *testing.T) {
	checker := NewTLSChecker(2 * time.Second)
	ctx := context.Background()

	supported := checker.ProbeSSL30(ctx, "127.0.0.1:1")
	if supported {
		t.Error("expected false for unreachable server")
	}
}

func TestProbeSSL30_NonSSLServer(t *testing.T) {
	// Start a TCP server that responds with non-TLS data
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		// Read the ClientHello and respond with HTTP
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()

	checker := NewTLSChecker(2 * time.Second)
	ctx := context.Background()

	supported := checker.ProbeSSL30(ctx, ln.Addr().String())
	if supported {
		t.Error("expected false for non-SSL server")
	}
}

func TestProbeSSL30_MockSSL30Server(t *testing.T) {
	// Start a TCP server that responds with a mock SSLv3 ServerHello
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		// Read the ClientHello
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		// Respond with a minimal SSLv3 ServerHello
		serverHello := buildMockSSL30ServerHello()
		_, _ = conn.Write(serverHello)
	}()

	checker := NewTLSChecker(2 * time.Second)
	ctx := context.Background()

	supported := checker.ProbeSSL30(ctx, ln.Addr().String())
	if !supported {
		t.Error("expected true for mock SSLv3 server")
	}
}

func TestProbeSSL30_TLS12ServerHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		// Respond with TLS 1.2 ServerHello (version 3.3)
		response := []byte{
			recordTypeHandshake, 3, 3, // TLS 1.2 record
			0, 6, // length
			handshakeTypeServerHello, 0, 0, 2, // handshake header
			3, 3, // server version: TLS 1.2
		}
		_, _ = conn.Write(response)
	}()

	checker := NewTLSChecker(2 * time.Second)
	ctx := context.Background()

	supported := checker.ProbeSSL30(ctx, ln.Addr().String())
	if supported {
		t.Error("expected false for TLS 1.2 server responding to SSLv3 probe")
	}
}

func TestProbeSSL30_OversizedRecordLen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		// SSLv3 handshake record with recordLen exceeding maxTLSRecordPayload
		response := []byte{
			recordTypeHandshake, sslVersionSSL30Major, sslVersionSSL30Minor,
			0xFF, 0xFF, // recordLen = 65535, exceeds 16384
			handshakeTypeServerHello, 0, 0, 2,
			sslVersionSSL30Major, sslVersionSSL30Minor,
		}
		_, _ = conn.Write(response)
	}()

	checker := NewTLSChecker(2 * time.Second)
	ctx := context.Background()

	supported := checker.ProbeSSL30(ctx, ln.Addr().String())
	if supported {
		t.Error("expected false for oversized record length")
	}
}

// buildMockSSL30ServerHello constructs a minimal SSLv3 ServerHello response.
func buildMockSSL30ServerHello() []byte {
	// ServerHello body: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1)
	body := []byte{
		sslVersionSSL30Major, sslVersionSSL30Minor, // server version: SSL 3.0
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session ID length
	body = append(body, 0, 0x2f)             // cipher: TLS_RSA_WITH_AES_128_CBC_SHA
	body = append(body, 0)                   // compression: null

	// Handshake header
	handshake := []byte{handshakeTypeServerHello}
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record
	record := []byte{recordTypeHandshake, sslVersionSSL30Major, sslVersionSSL30Minor}
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}
