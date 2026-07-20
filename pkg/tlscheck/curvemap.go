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

// profileToGoCurve maps TLS profile group names (Mozilla/OpenSSL/IANA)
// to Go's tls.CurveID.String() output.
var profileToGoCurve = map[string]string{
	"secp256r1": "CurveP256",
	"secp384r1": "CurveP384",
	"secp521r1": "CurveP521",
}

var goCurveToProfile map[string]string

func init() {
	goCurveToProfile = make(map[string]string, len(profileToGoCurve))
	for profile, goName := range profileToGoCurve {
		goCurveToProfile[goName] = profile
	}
}

// ProfileToGoCurve converts a profile/Mozilla group name to the Go CurveID.String() name.
// Names that already match Go output (X25519, X25519MLKEM768, etc.) pass through unchanged.
func ProfileToGoCurve(name string) string {
	if goName, ok := profileToGoCurve[name]; ok {
		return goName
	}
	return name
}

// GoCurveToProfile converts a Go CurveID.String() name to the profile/Mozilla group name.
// Names that already match profile format pass through unchanged.
func GoCurveToProfile(name string) string {
	if profileName, ok := goCurveToProfile[name]; ok {
		return profileName
	}
	return name
}
