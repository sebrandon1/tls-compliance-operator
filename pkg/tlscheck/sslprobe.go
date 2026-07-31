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
	"encoding/binary"
	"io"
	"net"
	"time"
)

// SSL protocol version bytes
const (
	sslVersionSSL30Major = 3
	sslVersionSSL30Minor = 0

	// TLS record types
	recordTypeHandshake = 22
	// Handshake message types
	handshakeTypeClientHello = 1
	handshakeTypeServerHello = 2

	// maxTLSRecordPayload is the maximum TLS record payload per RFC 8446 §5.1.
	maxTLSRecordPayload = 16384
)

// ssl30ClientHello is the pre-built SSLv3 ClientHello (static, never changes).
var ssl30ClientHello = buildSSL30ClientHello()

// buildSSL30ClientHello constructs a minimal SSLv3 ClientHello message.
// The ClientHello offers a small set of SSLv3 cipher suites to maximize
// compatibility with servers that still support SSLv3.
func buildSSL30ClientHello() []byte {
	// Cipher suites commonly supported by SSLv3 servers
	cipherSuites := []uint16{
		0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x0004, // TLS_RSA_WITH_RC4_128_MD5
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
	}

	// Build the ClientHello handshake body
	var hello []byte

	// Client version: SSL 3.0 (3, 0)
	hello = append(hello, sslVersionSSL30Major, sslVersionSSL30Minor)

	// Random: 32 bytes of zeros (sufficient for detection)
	hello = append(hello, make([]byte, 32)...)

	// Session ID length: 0
	hello = append(hello, 0)

	// Cipher suites
	csLen := len(cipherSuites) * 2
	hello = append(hello, byte(csLen>>8), byte(csLen))
	for _, cs := range cipherSuites {
		hello = append(hello, byte(cs>>8), byte(cs))
	}

	// Compression methods: 1 method (null)
	hello = append(hello, 1, 0)

	// Wrap in handshake header (type + 3-byte length)
	handshake := []byte{handshakeTypeClientHello}
	handshake = append(handshake, byte(len(hello)>>16), byte(len(hello)>>8), byte(len(hello)))
	handshake = append(handshake, hello...)

	// Wrap in TLS record (type + version + 2-byte length)
	record := []byte{recordTypeHandshake, sslVersionSSL30Major, sslVersionSSL30Minor}
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

// ProbeSSL30 sends a raw SSLv3 ClientHello and checks if the server responds
// with an SSLv3 ServerHello, indicating SSLv3 support.
func (c *TLSChecker) ProbeSSL30(ctx context.Context, addr string) bool {
	dialer := &net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	}

	if _, err := conn.Write(ssl30ClientHello); err != nil {
		return false
	}

	return isSSL30ServerHello(conn)
}

// isSSL30ServerHello reads the server's response and checks if it's an SSLv3
// ServerHello (record version 3.0 with handshake type ServerHello).
func isSSL30ServerHello(conn net.Conn) bool {
	// Read TLS record header: type(1) + version(2) + length(2)
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}

	// Must be a handshake record
	if header[0] != recordTypeHandshake {
		return false
	}

	// Check version is SSL 3.0 (3.0)
	if header[1] != sslVersionSSL30Major || header[2] != sslVersionSSL30Minor {
		return false
	}

	// Read enough of the handshake to check the message type and version
	recordLen := binary.BigEndian.Uint16(header[3:5])
	if recordLen < 6 || recordLen > maxTLSRecordPayload {
		return false
	}

	// Read handshake header: type(1) + length(3) + version(2)
	handshakeHeader := make([]byte, 6)
	if _, err := io.ReadFull(conn, handshakeHeader); err != nil {
		return false
	}

	// Must be ServerHello
	if handshakeHeader[0] != handshakeTypeServerHello {
		return false
	}

	// Server version in the ServerHello body must be SSL 3.0
	return handshakeHeader[4] == sslVersionSSL30Major && handshakeHeader[5] == sslVersionSSL30Minor
}
