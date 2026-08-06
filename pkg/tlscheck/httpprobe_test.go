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
	"strings"
	"testing"
	"time"
)

func TestProbeHTTP_HTTPServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	got := checker.probeHTTP(context.Background(), addr.String(), addr.IP.String())
	if !got {
		t.Error("expected probeHTTP to return true for HTTP server")
	}
}

func TestProbeHTTP_HTTPErrorResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	got := checker.probeHTTP(context.Background(), addr.String(), addr.IP.String())
	if !got {
		t.Error("expected probeHTTP to return true for HTTP error response")
	}
}

func TestProbeHTTP_NonHTTPServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("220 mail.example.com ESMTP\r\n"))
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	got := checker.probeHTTP(context.Background(), addr.String(), addr.IP.String())
	if got {
		t.Error("expected probeHTTP to return false for non-HTTP server")
	}
}

func TestProbeHTTP_SilentServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Accept but never respond — deadline will expire
			time.Sleep(5 * time.Second)
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	got := checker.probeHTTP(context.Background(), addr.String(), addr.IP.String())
	if got {
		t.Error("expected probeHTTP to return false for silent server")
	}
}

func TestProbeHTTP_ImmediateClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	checker := NewTLSChecker(2 * time.Second)
	got := checker.probeHTTP(context.Background(), addr.String(), addr.IP.String())
	if got {
		t.Error("expected probeHTTP to return false when server closes immediately")
	}
}

func TestProbeHTTP_NoServer(t *testing.T) {
	checker := NewTLSChecker(2 * time.Second)
	got := checker.probeHTTP(context.Background(), "127.0.0.1:1", "127.0.0.1")
	if got {
		t.Error("expected probeHTTP to return false for unreachable server")
	}
}

func TestProbeHTTP_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	checker := NewTLSChecker(2 * time.Second)
	got := checker.probeHTTP(ctx, "127.0.0.1:80", "127.0.0.1")
	if got {
		t.Error("expected probeHTTP to return false with cancelled context")
	}
}

func TestProbeHTTP_CRLFInjection(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		wantContains string
		wantAbsent   string
	}{
		{
			name:         "CRLF pair",
			host:         "evil.com\r\nX-Injected: true\r\n",
			wantContains: "Host: evil.com",
			wantAbsent:   "\r\nX-Injected:",
		},
		{
			name:         "bare LF",
			host:         "evil.com\nX-Injected: true",
			wantContains: "Host: evil.com",
			wantAbsent:   "\nX-Injected:",
		},
		{
			name:         "bare CR",
			host:         "evil.com\rX-Injected: true",
			wantContains: "Host: evil.com",
			wantAbsent:   "\rX-Injected:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received := make(chan string, 1)

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()

			go func() {
				conn, err := listener.Accept()
				if err != nil {
					received <- ""
					return
				}
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				received <- string(buf[:n])
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				_ = conn.Close()
			}()

			addr := listener.Addr().(*net.TCPAddr)
			checker := NewTLSChecker(2 * time.Second)
			checker.probeHTTP(context.Background(), addr.String(), tt.host)

			receivedRequest := <-received
			if strings.Contains(receivedRequest, tt.wantAbsent) {
				t.Errorf("injection detected: found %q in request", tt.wantAbsent)
			}
			if !strings.Contains(receivedRequest, tt.wantContains) {
				t.Errorf("expected %q in request, got: %q", tt.wantContains, receivedRequest)
			}
		})
	}
}
