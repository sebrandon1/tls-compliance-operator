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
	"crypto/fips140"
	"os"
	"strings"
)

const procFIPSPath = "/proc/sys/crypto/fips_enabled"

// Detect returns true if the system is running in FIPS mode.
// Procfs reflects the kernel FIPS flag; the Go runtime check covers
// FIPS-compiled binaries where the kernel flag may not be exposed.
func Detect() bool {
	if readFIPSFromProcfs(procFIPSPath) {
		return true
	}
	return fips140.Enabled()
}

func readFIPSFromProcfs(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}
