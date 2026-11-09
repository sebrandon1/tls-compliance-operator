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
	"crypto/tls"
	"testing"
	"time"
)

func TestParseTLSVersions(t *testing.T) {
	tests := []struct {
		name  string
		names []string
		want  map[uint16]bool
	}{
		{name: "empty", names: nil, want: nil},
		{name: "all four", names: []string{"1.0", "1.1", "1.2", "1.3"}, want: map[uint16]bool{
			tls.VersionTLS10: true, tls.VersionTLS11: true, tls.VersionTLS12: true, tls.VersionTLS13: true,
		}},
		{name: "prefix and case", names: []string{"TLS1.2", " tls1.3 "}, want: map[uint16]bool{
			tls.VersionTLS12: true, tls.VersionTLS13: true,
		}},
		{name: "compact spelling", names: []string{"12"}, want: map[uint16]bool{tls.VersionTLS12: true}},
		{name: "unknown only", names: []string{"2.0"}, want: nil},
		{name: "unknown ignored", names: []string{"1.2", "bogus"}, want: map[uint16]bool{tls.VersionTLS12: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTLSVersions(tt.names)
			if len(got) != len(tt.want) {
				t.Fatalf("ParseTLSVersions(%v) = %v, want %v", tt.names, got, tt.want)
			}
			for version := range tt.want {
				if !got[version] {
					t.Errorf("ParseTLSVersions(%v) missing version %#x", tt.names, version)
				}
			}
		})
	}
}

func TestCheckOptionsContextRoundTrip(t *testing.T) {
	if _, ok := CheckOptionsFrom(context.Background()); ok {
		t.Fatal("expected no options on a bare context")
	}

	enumerate := false
	opts := CheckOptions{Timeout: 3 * time.Second, TLSVersions: []string{"1.2"}, EnumerateCiphers: &enumerate}
	got, ok := CheckOptionsFrom(WithCheckOptions(context.Background(), opts))
	if !ok {
		t.Fatal("expected options on the derived context")
	}
	if got.Timeout != opts.Timeout {
		t.Errorf("Timeout = %v, want %v", got.Timeout, opts.Timeout)
	}
	if got.EnumerateCiphers == nil || *got.EnumerateCiphers {
		t.Errorf("EnumerateCiphers = %v, want false", got.EnumerateCiphers)
	}
	if len(got.TLSVersions) != 1 || got.TLSVersions[0] != "1.2" {
		t.Errorf("TLSVersions = %v, want [1.2]", got.TLSVersions)
	}
}

func TestTLSChecker_CheckEndpoint_VersionRestriction(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	ctx := WithCheckOptions(context.Background(), CheckOptions{TLSVersions: []string{"1.2"}})

	result, err := checker.CheckEndpoint(ctx, host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}
	if !result.SupportsTLS12 {
		t.Error("expected TLS 1.2 to be probed and supported")
	}
	if result.SupportsTLS13 {
		t.Error("expected TLS 1.3 to be skipped by the version restriction")
	}
	if result.SupportsSSL30 {
		t.Error("expected the SSLv3 probe to be skipped when versions are restricted")
	}
}

func TestTLSChecker_CheckEndpoint_CipherEnumerationDisabled(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	defer cleanup()

	enumerate := false
	checker := NewTLSChecker(2 * time.Second)
	ctx := WithCheckOptions(context.Background(), CheckOptions{EnumerateCiphers: &enumerate})

	result, err := checker.CheckEndpoint(ctx, host, port)
	if err != nil {
		t.Fatalf("CheckEndpoint() error = %v", err)
	}
	for version, suites := range result.CipherSuites {
		if len(suites) != 1 {
			t.Errorf("version %s: got %d cipher suites %v, want only the negotiated one", version, len(suites), suites)
		}
	}
}

func TestTLSChecker_CheckEndpoint_TimeoutOverride(t *testing.T) {
	cert, _ := generateTestCert(t)
	host, port, cleanup := startTLSServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	defer cleanup()

	checker := NewTLSChecker(2 * time.Second)
	ctx := WithCheckOptions(context.Background(), CheckOptions{Timeout: time.Nanosecond})

	result, err := checker.CheckEndpoint(ctx, host, port)
	if err == nil && result != nil && result.SupportsTLS12 {
		t.Fatal("expected the nanosecond timeout override to prevent a successful handshake")
	}
}
