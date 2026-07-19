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

package fips

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFIPSFromProcfs(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		exists   bool
		expected bool
	}{
		{
			name:     "file contains 1",
			content:  "1\n",
			exists:   true,
			expected: true,
		},
		{
			name:     "file contains 1 without newline",
			content:  "1",
			exists:   true,
			expected: true,
		},
		{
			name:     "file contains 0",
			content:  "0\n",
			exists:   true,
			expected: false,
		},
		{
			name:     "empty file",
			content:  "",
			exists:   true,
			expected: false,
		},
		{
			name:     "file does not exist",
			exists:   false,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			if tc.exists {
				path = filepath.Join(t.TempDir(), "fips_enabled")
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				path = filepath.Join(t.TempDir(), "nonexistent")
			}

			got := readFIPSFromProcfs(path)
			if got != tc.expected {
				t.Errorf("readFIPSFromProcfs(%q) = %v, want %v", path, got, tc.expected)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	// Smoke test: Detect() should not panic and should return a bool.
	// On non-FIPS systems (dev machines), this will return false.
	got := Detect()
	t.Logf("Detect() = %v", got)
	_ = got
}
