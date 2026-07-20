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

import "testing"

func TestProfileToGoCurve(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"secp256r1", "CurveP256"},
		{"secp384r1", "CurveP384"},
		{"secp521r1", "CurveP521"},
		{"X25519", "X25519"},
		{"X25519MLKEM768", "X25519MLKEM768"},
		{"SecP256r1MLKEM768", "SecP256r1MLKEM768"},
		{"unknown", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ProfileToGoCurve(tc.input)
			if got != tc.expected {
				t.Errorf("ProfileToGoCurve(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestGoCurveToProfile(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"CurveP256", "secp256r1"},
		{"CurveP384", "secp384r1"},
		{"CurveP521", "secp521r1"},
		{"X25519", "X25519"},
		{"X25519MLKEM768", "X25519MLKEM768"},
		{"unknown", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := GoCurveToProfile(tc.input)
			if got != tc.expected {
				t.Errorf("GoCurveToProfile(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}
