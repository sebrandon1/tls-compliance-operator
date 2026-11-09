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

package tlsprofile

import "testing"

func TestProfileFromSpec(t *testing.T) {
	profile, err := ProfileFromSpec("VersionTLS13", []string{"TLS_AES_128_GCM_SHA256"}, []string{"X25519"})
	if err != nil {
		t.Fatalf("ProfileFromSpec() error = %v", err)
	}
	if profile.Type != ProfileTypeCustom {
		t.Errorf("Type = %q, want %q", profile.Type, ProfileTypeCustom)
	}
	if profile.MinTLSVersion != VersionTLS13 {
		t.Errorf("MinTLSVersion = %q, want %q", profile.MinTLSVersion, VersionTLS13)
	}
	if len(profile.Ciphers) != 1 || profile.Ciphers[0] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("Ciphers = %v", profile.Ciphers)
	}
	if len(profile.Groups) != 1 || profile.Groups[0] != "X25519" {
		t.Errorf("Groups = %v", profile.Groups)
	}
}

func TestProfileFromSpec_UnknownVersion(t *testing.T) {
	if _, err := ProfileFromSpec("VersionTLS99", nil, nil); err == nil {
		t.Fatal("ProfileFromSpec() error = nil, want an error for an unknown version")
	}
}
