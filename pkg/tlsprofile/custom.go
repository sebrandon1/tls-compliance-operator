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

import "fmt"

// ProfileFromSpec builds a Profile from a cluster-defined TLS security
// profile. The minimum version uses the OpenShift spelling (VersionTLS12 and
// so on); ciphers and groups are optional.
func ProfileFromSpec(minVersion string, ciphers, groups []string) (Profile, error) {
	version := TLSVersion(minVersion)
	if _, ok := tlsVersionOrder[version]; !ok {
		return Profile{}, fmt.Errorf("unknown TLS version %q", minVersion)
	}
	return Profile{
		Type:          ProfileTypeCustom,
		MinTLSVersion: version,
		Ciphers:       ciphers,
		Groups:        groups,
	}, nil
}
