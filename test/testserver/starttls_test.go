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

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	// preludeTestDeadline keeps a broken prelude from hanging the suite.
	preludeTestDeadline = 10 * time.Second

	mysqlGreeting = "\x08\x00\x00\x00" + "\x0a\x00\x00\x00\x01\x00\x00\x00"
)

// preludeStep is one half of a protocol's cleartext exchange: either the exact
// bytes the server must write next, or a message the client sends.
type preludeStep struct {
	read  string
	write string
}

// preludeCase drives one STARTTLS protocol from the client side. The first
// step of every protocol except XMPP is the server's greeting, so the reads
// pin the wire bytes the parity fixtures depend on.
type preludeCase struct {
	protocol string
	steps    []preludeStep
}

// mysqlSSLRequest builds the 36-byte SSLRequest a MySQL client sends to switch
// the connection to TLS.
func mysqlSSLRequest() []byte {
	request := make([]byte, 36)
	binary.LittleEndian.PutUint32(request[4:8], 0x0800) // CLIENT_SSL
	return request
}

var preludeCases = []preludeCase{
	{
		protocol: "mysql",
		steps: []preludeStep{
			{read: mysqlGreeting},
			{write: string(mysqlSSLRequest())},
		},
	},
	{
		protocol: "smtp",
		steps: []preludeStep{
			{read: "220 test.example.com ESMTP\r\n"},
			{write: "EHLO test.example.com\r\n"},
			{read: "250-test.example.com\r\n250-STARTTLS\r\n250 OK\r\n"},
			{write: "STARTTLS\r\n"},
			{read: "220 Go ahead\r\n"},
		},
	},
	{
		protocol: "imap",
		steps: []preludeStep{
			{read: "* OK IMAP4rev1 Service Ready\r\n"},
			{write: "a001 STARTTLS\r\n"},
			{read: "a001 OK Begin TLS negotiation\r\n"},
		},
	},
	{
		protocol: "pop3",
		steps: []preludeStep{
			{read: "+OK POP3 ready\r\n"},
			{write: "STLS\r\n"},
			{read: "+OK Begin TLS negotiation\r\n"},
		},
	},
	{
		protocol: "lmtp",
		steps: []preludeStep{
			{read: "220 test.example.com LMTP\r\n"},
			{write: "LHLO test.example.com\r\n"},
			{read: "250-test.example.com\r\n250-STARTTLS\r\n250 OK\r\n"},
			{write: "STARTTLS\r\n"},
			{read: "220 Go ahead\r\n"},
		},
	},
	{
		protocol: "nntp",
		steps: []preludeStep{
			{read: "200 NNTP ready\r\n"},
			{write: "STARTTLS\r\n"},
			{read: "382 Continue with TLS\r\n"},
		},
	},
	{
		protocol: "sieve",
		steps: []preludeStep{
			{read: "OK Sieve ready\r\n"},
			{write: "STARTTLS\r\n"},
			{read: "OK Begin TLS negotiation\r\n"},
		},
	},
	{
		protocol: "ftp",
		steps: []preludeStep{
			{read: "220 FTP ready\r\n"},
			{write: "AUTH TLS\r\n"},
			{read: "234 Proceed with negotiation\r\n"},
		},
	},
	{
		// XMPP is client-first: the server answers the stream header.
		protocol: "xmpp",
		steps: []preludeStep{
			{write: "<stream:stream to='test.example.com'>"},
			{read: "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>"},
			{write: "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"},
			{read: "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"},
		},
	},
}

// drivePrelude runs the client half of the exchange, asserting that the server
// writes exactly the expected bytes at every read step.
func drivePrelude(t *testing.T, conn net.Conn, r *bufio.Reader, steps []preludeStep) {
	t.Helper()
	for i, step := range steps {
		if step.write != "" {
			if _, err := io.WriteString(conn, step.write); err != nil {
				t.Fatalf("step %d: writing %q: %v", i, step.write, err)
			}
			continue
		}
		got := make([]byte, len(step.read))
		if _, err := io.ReadFull(r, got); err != nil {
			t.Fatalf("step %d: reading %d greeting bytes: %v", i, len(step.read), err)
		}
		if string(got) != step.read {
			t.Errorf("step %d: server wrote %q, want %q", i, got, step.read)
		}
	}
}

func TestServePrelude_Protocols(t *testing.T) {
	for _, tc := range preludeCases {
		t.Run(tc.protocol, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()

			deadline := time.Now().Add(preludeTestDeadline)
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatalf("SetDeadline() on the server side: %v", err)
			}
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatalf("SetDeadline() on the client side: %v", err)
			}

			done := make(chan error, 1)
			go func() { done <- servePrelude(server, tc.protocol) }()

			drivePrelude(t, client, bufio.NewReader(client), tc.steps)

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("servePrelude(%q) error = %v", tc.protocol, err)
				}
			case <-time.After(preludeTestDeadline):
				t.Fatalf("servePrelude(%q) did not return after the exchange", tc.protocol)
			}
		})
	}
}

func TestServePrelude_UnknownProtocol(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	err := servePrelude(server, "gopher")
	if err == nil {
		t.Fatal("servePrelude(gopher) error = nil, want an unsupported-protocol error")
	}
	if !strings.Contains(err.Error(), "unsupported STARTTLS protocol") {
		t.Errorf("servePrelude(gopher) error = %v, want it to name the unsupported protocol", err)
	}
}

func TestPreludeMySQL_RejectsClientWithoutSSLRequest(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	deadline := time.Now().Add(preludeTestDeadline)
	_ = server.SetDeadline(deadline)
	_ = client.SetDeadline(deadline)

	done := make(chan error, 1)
	go func() { done <- preludeMySQL(server) }()

	greeting := make([]byte, len(mysqlGreeting))
	if _, err := io.ReadFull(bufio.NewReader(client), greeting); err != nil {
		t.Fatalf("reading the MySQL greeting: %v", err)
	}
	// Capabilities of zero mean the client never asked for CLIENT_SSL.
	if _, err := client.Write(make([]byte, 36)); err != nil {
		t.Fatalf("writing the SSLRequest: %v", err)
	}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "CLIENT_SSL") {
			t.Fatalf("preludeMySQL() error = %v, want a CLIENT_SSL error", err)
		}
	case <-time.After(preludeTestDeadline):
		t.Fatal("preludeMySQL() did not reject the request without CLIENT_SSL")
	}
}

func TestReadUntil_GivesUpWhenTheTerminatorNeverArrives(t *testing.T) {
	err := readUntil(bufio.NewReader(strings.NewReader(strings.Repeat("a", 8200))), ">")
	if err == nil {
		t.Fatal("readUntil() error = nil, want an error for an 8192-byte stream without the terminator")
	}
	if !strings.Contains(err.Error(), `">" not found`) {
		t.Errorf("readUntil() error = %v, want it to name the missing terminator", err)
	}
}

// TestServeSTARTTLS_UpgradesToTLS runs the whole flow over a real TCP socket:
// cleartext prelude, then a TLS handshake on the same connection.
func TestServeSTARTTLS_UpgradesToTLS(t *testing.T) {
	tlsCfg, err := buildTLSConfig(config{minVersion: "1.2", maxVersion: "1.3", certCN: "testserver"})
	if err != nil {
		t.Fatalf("buildTLSConfig() error = %v", err)
	}

	for _, tc := range preludeCases {
		t.Run(tc.protocol, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen() error = %v", err)
			}
			defer listener.Close()

			done := make(chan error, 1)
			go func() { done <- serveSTARTTLSListener(listener, tc.protocol, tlsCfg) }()

			conn, err := net.DialTimeout("tcp", listener.Addr().String(), preludeTestDeadline)
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(preludeTestDeadline)); err != nil {
				t.Fatalf("SetDeadline() error = %v", err)
			}

			drivePrelude(t, conn, bufio.NewReader(conn), tc.steps)

			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			if err := tlsConn.Handshake(); err != nil {
				t.Fatalf("TLS handshake after the %s prelude: %v", tc.protocol, err)
			}
			state := tlsConn.ConnectionState()
			if !state.HandshakeComplete {
				t.Error("HandshakeComplete = false after a successful handshake")
			}
			if state.Version < tls.VersionTLS12 {
				t.Errorf("negotiated version = %#x, want TLS 1.2 or newer", state.Version)
			}
			if len(state.PeerCertificates) == 0 {
				t.Error("PeerCertificates = empty, want the test server's certificate")
			}

			// Closing the listener ends the accept loop.
			if err := listener.Close(); err != nil {
				t.Fatalf("closing the listener: %v", err)
			}
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("serveSTARTTLSListener() error = %v after Close(), want net.ErrClosed", err)
				}
			case <-time.After(preludeTestDeadline):
				t.Fatal("the accept loop did not stop after the listener was closed")
			}
		})
	}
}

func TestServeSTARTTLS_ListenError(t *testing.T) {
	// Holding the port makes Listen fail without depending on DNS.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	if err := serveSTARTTLS(listener.Addr().String(), "smtp", &tls.Config{}); err == nil {
		t.Fatal("serveSTARTTLS() error = nil, want an address-in-use error")
	}
}

// TestHandleSTARTTLSConn_ClientDisconnectsDuringPrelude pins the failure mode
// that otherwise only shows up as an opaque e2e timeout: a client that hangs up
// before finishing the prelude must not take the accept loop down with it.
func TestHandleSTARTTLSConn_ClientDisconnectsDuringPrelude(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() { done <- serveSTARTTLSListener(listener, "smtp", &tls.Config{}) }()

	greeting := "220 test.example.com ESMTP\r\n"
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), preludeTestDeadline)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(preludeTestDeadline))
	if _, err := io.ReadFull(bufio.NewReader(conn), make([]byte, len(greeting))); err != nil {
		t.Fatalf("reading the SMTP greeting: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("closing the aborted connection: %v", err)
	}

	// A second connection is still served, so the accept loop survived.
	next, err := net.DialTimeout("tcp", listener.Addr().String(), preludeTestDeadline)
	if err != nil {
		t.Fatalf("Dial() after the aborted prelude: %v", err)
	}
	defer next.Close()
	_ = next.SetDeadline(time.Now().Add(preludeTestDeadline))
	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(bufio.NewReader(next), got); err != nil {
		t.Fatalf("reading the second SMTP greeting: %v", err)
	}
	if string(got) != greeting {
		t.Errorf("second greeting = %q, want %q", got, greeting)
	}
}
