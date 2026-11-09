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
	"strings"
	"time"
)

// CheckOptions carries per-endpoint overrides for a single TLS check. Every
// field is optional; a zero value keeps the checker's configured behavior.
// Options travel on the context so the Checker interface stays unchanged and
// callers that do not need overrides pay nothing.
type CheckOptions struct {
	// Timeout overrides the per-probe socket timeout when positive.
	Timeout time.Duration
	// TLSVersions restricts which TLS versions are probed, using the "1.0",
	// "1.1", "1.2" and "1.3" spellings. Empty probes every version.
	TLSVersions []string
	// EnumerateCiphers overrides the checker's cipher enumeration setting.
	EnumerateCiphers *bool
	// ClientCert overrides the client certificate presented to mTLS endpoints.
	ClientCert *tls.Certificate
}

type checkOptionsKey struct{}

// WithCheckOptions returns a context that makes CheckEndpoint apply opts.
func WithCheckOptions(ctx context.Context, opts CheckOptions) context.Context {
	return context.WithValue(ctx, checkOptionsKey{}, opts)
}

// CheckOptionsFrom returns the options attached to ctx, if any.
func CheckOptionsFrom(ctx context.Context) (CheckOptions, bool) {
	opts, ok := ctx.Value(checkOptionsKey{}).(CheckOptions)
	return opts, ok
}

// ParseTLSVersions converts version spellings such as "1.2" or "TLS1.2" into
// the set of crypto/tls version constants. An unknown spelling is ignored;
// callers that must reject bad input should validate it first.
func ParseTLSVersions(names []string) map[uint16]bool {
	if len(names) == 0 {
		return nil
	}
	allowed := make(map[uint16]bool, len(names))
	for _, name := range names {
		if version, ok := parseTLSVersion(name); ok {
			allowed[version] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

// withOverrides returns the checker to use for one check, applying any
// context-carried options, plus the set of TLS versions to probe (nil means
// every version). The receiver is never mutated: a shallow copy is made only
// when an option actually changes behavior.
func (c *TLSChecker) withOverrides(ctx context.Context) (*TLSChecker, map[uint16]bool) {
	opts, ok := CheckOptionsFrom(ctx)
	if !ok {
		return c, nil
	}

	allowed := ParseTLSVersions(opts.TLSVersions)

	patched := *c
	changed := false
	if opts.Timeout > 0 {
		patched.Timeout = opts.Timeout
		changed = true
	}
	if opts.ClientCert != nil {
		patched.ClientCert = opts.ClientCert
		changed = true
	}
	if opts.EnumerateCiphers != nil {
		patched.EnumerateCiphers = *opts.EnumerateCiphers
		changed = true
	}
	if !changed {
		return c, allowed
	}
	return &patched, allowed
}

// parseTLSVersion maps a version spelling to its crypto/tls constant.
func parseTLSVersion(name string) (uint16, bool) {
	switch strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "tls") {
	case "1.0", "10":
		return tls.VersionTLS10, true
	case "1.1", "11":
		return tls.VersionTLS11, true
	case "1.2", "12":
		return tls.VersionTLS12, true
	case "1.3", "13":
		return tls.VersionTLS13, true
	default:
		return 0, false
	}
}
