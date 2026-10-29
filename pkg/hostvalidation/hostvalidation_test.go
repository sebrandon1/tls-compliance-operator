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

package hostvalidation

import (
	"errors"
	"net"
	"testing"
)

func TestIsReservedIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		reserved bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"link-local metadata", "169.254.169.254", true},
		{"rfc1918 10.x", "10.0.0.1", true},
		{"rfc1918 172.16.x", "172.16.0.1", true},
		{"rfc1918 192.168.x", "192.168.1.1", true},
		{"link-local v6", "fe80::1", true},
		{"unique local v6", "fd00::1", true},
		{"unspecified", "0.0.0.0", true},
		{"public IP", "8.8.8.8", false},
		{"public v6", "2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			if got := IsReservedIP(ip); got != tt.reserved {
				t.Errorf("IsReservedIP(%s) = %v, want %v", tt.ip, got, tt.reserved)
			}
		})
	}
}

func TestIsInternalHostname(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		internal bool
	}{
		{"localhost", "localhost", true},
		{"localhost uppercase", "LOCALHOST", true},
		{"google metadata", "metadata.google.internal", true},
		{"cluster local allowed", "my-svc.default.svc.cluster.local", false},
		{"dot localhost", "sub.localhost", true},
		{"external", "example.com", false},
		{"external with dots", "api.prod.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsInternalHostname(tt.host); got != tt.internal {
				t.Errorf("IsInternalHostname(%q) = %v, want %v", tt.host, got, tt.internal)
			}
		})
	}
}

func TestIsSafeHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		safe bool
	}{
		{"public domain", "example.com", true},
		{"public IP", "8.8.8.8", true},
		{"public v6", "2001:4860:4860::8888", true},
		{"cloud metadata IP", "169.254.169.254", false},
		{"loopback v4", "127.0.0.1", false},
		{"loopback v6", "::1", false},
		{"localhost name", "localhost", false},
		{"google metadata name", "metadata.google.internal", false},
		{"cluster-local svc allowed", "redis.default.svc.cluster.local", true},
		{"private 10.x", "10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSafeHost(tt.host); got != tt.safe {
				t.Errorf("IsSafeHost(%q) = %v, want %v", tt.host, got, tt.safe)
			}
		})
	}
}

func TestDialControl(t *testing.T) {
	tests := []struct {
		name    string
		address string
		blocked bool
		wantErr bool
	}{
		{"public v4", "8.8.8.8:443", false, false},
		{"public v6", "[2001:4860:4860::8888]:443", false, false},
		{"loopback", "127.0.0.1:443", true, true},
		{"metadata", "169.254.169.254:80", true, true},
		{"cluster IP", "172.30.0.1:443", true, true},
		{"ipv4-mapped metadata", "[::ffff:169.254.169.254]:80", true, true},
		{"link-local with zone", "[fe80::1%eth0]:443", true, true},
		{"missing port", "8.8.8.8", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DialControl("tcp", tt.address, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DialControl(%q) error = %v, wantErr %v", tt.address, err, tt.wantErr)
			}
			if got := errors.Is(err, ErrReservedAddress); got != tt.blocked {
				t.Errorf("DialControl(%q) blocked = %v, want %v (err %v)", tt.address, got, tt.blocked, err)
			}
		})
	}
}
