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
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Checker defines the interface for TLS endpoint checking
type Checker interface {
	CheckEndpoint(ctx context.Context, host string, port int) (*TLSCheckResult, error)
}

// DefaultTimeout is the default timeout for individual TLS connection attempts
const DefaultTimeout = 5 * time.Second

// TLSChecker implements Checker using Go's crypto/tls
type TLSChecker struct {
	Timeout time.Duration
}

// NewTLSChecker creates a new TLSChecker with the given timeout
func NewTLSChecker(timeout time.Duration) *TLSChecker {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &TLSChecker{Timeout: timeout}
}

// tlsVersionInfo maps TLS version constants to their string names
var tlsVersionInfo = []struct {
	version uint16
	name    string
	field   func(*TLSCheckResult, bool)
}{
	{tls.VersionTLS10, "TLS 1.0", func(r *TLSCheckResult, v bool) { r.SupportsTLS10 = v }},
	{tls.VersionTLS11, "TLS 1.1", func(r *TLSCheckResult, v bool) { r.SupportsTLS11 = v }},
	{tls.VersionTLS12, "TLS 1.2", func(r *TLSCheckResult, v bool) { r.SupportsTLS12 = v }},
	{tls.VersionTLS13, "TLS 1.3", func(r *TLSCheckResult, v bool) { r.SupportsTLS13 = v }},
}

// CheckEndpoint checks the TLS configuration of an endpoint
func (c *TLSChecker) CheckEndpoint(ctx context.Context, host string, port int) (*TLSCheckResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	result := &TLSCheckResult{
		CipherSuites:     make(map[string][]string),
		NegotiatedCurves: make(map[string]string),
	}

	anySuccess := false
	var lastErrors []error

	for _, vi := range tlsVersionInfo {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		supported, cipherSuite, curveName, cert, err := c.tryTLSVersion(ctx, addr, host, vi.version)
		vi.field(result, supported)

		if supported && err == nil {
			anySuccess = true
			if cipherSuite != "" {
				result.CipherSuites[vi.name] = append(result.CipherSuites[vi.name], cipherSuite)
			}
			if curveName != "" {
				result.NegotiatedCurves[vi.name] = curveName
			}
			if cert != nil && result.Certificate == nil {
				result.Certificate = cert
			}
		} else if err != nil {
			lastErrors = append(lastErrors, err)
		}
	}

	result.CheckDuration = time.Since(start)

	if !anySuccess {
		result.FailureReason = classifyFailure(lastErrors)
		return result, fmt.Errorf("could not establish TLS connection to %s on any TLS version", addr)
	}

	return result, nil
}

// classifyFailure analyzes TLS connection errors to determine the failure category.
// Priority order: mTLS > NoTLS > Closed > Timeout > Filtered > Unreachable.
func classifyFailure(errs []error) FailureReason {
	if len(errs) == 0 {
		return FailureReasonUnreachable
	}

	var hasNoTLS, hasMTLS, hasTimeout, hasClosed bool

	for _, err := range errs {
		msg := err.Error()

		// Server requires client certificate
		if strings.Contains(msg, "certificate required") ||
			strings.Contains(msg, "bad certificate") {
			hasMTLS = true
		}

		// Port is open but not speaking TLS
		if strings.Contains(msg, "first record does not look like a TLS handshake") ||
			strings.Contains(msg, "oversized record") {
			hasNoTLS = true
		}

		// Connection refused — port is not listening
		if strings.Contains(msg, "connection refused") {
			hasClosed = true
		}

		// Timeout — check both net.Error interface and string patterns
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			hasTimeout = true
		}
		if strings.Contains(msg, "i/o timeout") ||
			strings.Contains(msg, "deadline exceeded") {
			hasTimeout = true
		}
	}

	// mTLS takes priority — the server IS speaking TLS, it just wants a client cert
	if hasMTLS {
		return FailureReasonMutualTLSRequired
	}
	if hasNoTLS {
		return FailureReasonNoTLS
	}
	if hasClosed {
		return FailureReasonClosed
	}
	if hasTimeout {
		// Pure timeout with no refusal suggests a firewall drop (filtered),
		// but we report Timeout since that's the observed behavior.
		return FailureReasonTimeout
	}

	return FailureReasonUnreachable
}

// tryTLSVersion attempts to connect with a specific TLS version
func (c *TLSChecker) tryTLSVersion(ctx context.Context, addr, serverName string, version uint16) (supported bool, cipherSuite string, curveName string, cert *CertificateDetails, err error) {
	dialer := &net.Dialer{
		Timeout: c.Timeout,
	}

	tlsConfig := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true, //nolint:gosec // We report cert info but don't enforce trust
		ServerName:         serverName,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return false, "", "", nil, err
	}
	defer conn.Close() //nolint:errcheck

	state := conn.ConnectionState()
	cipherSuiteName := tls.CipherSuiteName(state.CipherSuite)

	// Get negotiated curve name (zero value means RSA key exchange, no curve)
	var curve string
	if state.CurveID != 0 {
		curve = state.CurveID.String()
	}

	var certDetails *CertificateDetails
	if len(state.PeerCertificates) > 0 {
		certDetails = ParseCertificate(state.PeerCertificates[0])
	}

	return true, cipherSuiteName, curve, certDetails, nil
}

// RateLimitedChecker wraps a Checker with rate limiting
type RateLimitedChecker struct {
	checker Checker
	limiter *rate.Limiter
}

// NewRateLimitedChecker creates a new RateLimitedChecker
func NewRateLimitedChecker(checker Checker, ratePerSecond float64, burst int) *RateLimitedChecker {
	return &RateLimitedChecker{
		checker: checker,
		limiter: rate.NewLimiter(rate.Limit(ratePerSecond), burst),
	}
}

// CheckEndpoint rate-limits and then delegates to the wrapped checker
func (r *RateLimitedChecker) CheckEndpoint(ctx context.Context, host string, port int) (*TLSCheckResult, error) {
	if err := r.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed: %w", err)
	}
	return r.checker.CheckEndpoint(ctx, host, port)
}
