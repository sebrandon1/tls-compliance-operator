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

package v1alpha1

import (
	"testing"
)

func TestValidateTargetSpec_SSRF(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// Allowed external hosts
		{"external IPv4", "8.8.8.8", false},
		{"external IPv6", "2001:4860:4860::8888", false},
		{"external hostname", "example.com", false},
		{"external subdomain", "api.example.com", false},

		// Blocked: IPv4 loopback
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.0.0.2", "127.0.0.2", true},

		// Blocked: IPv6 loopback
		{"ipv6 loopback", "::1", true},

		// Blocked: link-local / cloud metadata
		{"link-local", "169.254.1.1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"ipv6 link-local", "fe80::1", true},

		// Blocked: RFC 1918 private
		{"10.x", "10.0.0.1", true},
		{"172.16.x", "172.16.0.1", true},
		{"172.31.x", "172.31.255.255", true},
		{"192.168.x", "192.168.1.1", true},

		// Blocked: IPv6 ULA
		{"ipv6 ULA", "fd00::1", true},

		// Blocked: unspecified
		{"unspecified", "0.0.0.0", true},

		// Allowed: 172.32.x is NOT RFC 1918
		{"172.32.x allowed", "172.32.0.1", false},

		// Blocked: internal hostnames
		{"localhost", "localhost", true},
		{"subdomain.localhost", "app.localhost", true},
		{"svc.cluster.local", "myapp.default.svc.cluster.local", true},
		{"metadata.google.internal", "metadata.google.internal", true},

		// Allowed: similar but not internal hostnames
		{"notlocalhost", "notlocalhost.com", false},
		{"cluster.local.example.com", "cluster.local.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &TLSComplianceTarget{}
			target.Spec.Host = tt.host
			target.Spec.Port = 443
			errs := validateTargetSpec(target)
			if tt.wantErr && len(errs) == 0 {
				t.Errorf("expected validation error for host %q, got none", tt.host)
			}
			if !tt.wantErr && len(errs) > 0 {
				t.Errorf("unexpected validation error for host %q: %v", tt.host, errs)
			}
		})
	}
}

func TestValidateTargetSpec_Wildcard(t *testing.T) {
	target := &TLSComplianceTarget{}
	target.Spec.Host = "*.example.com"
	target.Spec.Port = 443
	errs := validateTargetSpec(target)
	if len(errs) == 0 {
		t.Error("expected validation error for wildcard host")
	}
}

func TestValidateTargetSpec_InvalidDNS(t *testing.T) {
	target := &TLSComplianceTarget{}
	target.Spec.Host = "not a valid host!"
	target.Spec.Port = 443
	errs := validateTargetSpec(target)
	if len(errs) == 0 {
		t.Error("expected validation error for invalid DNS name")
	}
}
