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
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// Checker defines the interface for TLS endpoint checking
type Checker interface {
	CheckEndpoint(ctx context.Context, host string, port int) (*TLSCheckResult, error)
}

// DefaultTimeout is the default timeout for individual TLS connection attempts
const DefaultTimeout = 5 * time.Second

// DefaultALPNProtos is the list of ALPN protocols offered during TLS probing.
var DefaultALPNProtos = []string{"h2", "http/1.1"}

// TLSChecker implements Checker using Go's crypto/tls
type TLSChecker struct {
	Timeout          time.Duration
	ClientCert       *tls.Certificate
	EnumerateCiphers bool
}

// NewTLSChecker creates a new TLSChecker with the given timeout
func NewTLSChecker(timeout time.Duration) *TLSChecker {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &TLSChecker{Timeout: timeout, EnumerateCiphers: true}
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

// versionProbeResult holds the outcome of a single TLS version probe.
type versionProbeResult struct {
	name         string
	supported    bool
	cipherID     uint16
	cipherSuite  string
	curveName    string
	alpnProto    string
	cert         *CertificateDetails
	err          error
	cipherSuites []string
}

// CheckEndpoint checks the TLS configuration of an endpoint.
// TLS version probes and the SSLv3 probe run concurrently to minimize
// wall-clock time for unreachable hosts (1× timeout instead of 5×).
func (c *TLSChecker) CheckEndpoint(ctx context.Context, host string, port int) (*TLSCheckResult, error) {
	start := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	probeResults := make([]versionProbeResult, len(tlsVersionInfo))
	var ssl30Supported bool

	g, gctx := errgroup.WithContext(ctx)

	for i, vi := range tlsVersionInfo {
		g.Go(func() error {
			pr := &probeResults[i]
			pr.name = vi.name
			pr.supported, pr.cipherID, pr.cipherSuite, pr.curveName, pr.alpnProto, pr.cert, pr.err = c.tryTLSVersion(gctx, addr, host, vi.version)
			if pr.supported && pr.err == nil && pr.cipherSuite != "" && c.EnumerateCiphers && vi.version < tls.VersionTLS13 {
				pr.cipherSuites = c.enumerateCiphers(gctx, addr, host, vi.version, pr.cipherID)
			}
			return nil
		})
	}

	g.Go(func() error {
		ssl30Supported = c.ProbeSSL30(gctx, addr)
		return nil
	})

	_ = g.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	result := &TLSCheckResult{
		CipherSuites:     make(map[string][]string),
		ALPNProtocols:    make(map[string]string),
		NegotiatedCurves: make(map[string]string),
		SupportsSSL30:    ssl30Supported,
	}

	anySuccess := false
	var lastErrors []error

	for i := range probeResults {
		pr := &probeResults[i]
		tlsVersionInfo[i].field(result, pr.supported)

		if pr.supported && pr.err == nil {
			anySuccess = true
			if len(pr.cipherSuites) > 0 {
				result.CipherSuites[pr.name] = pr.cipherSuites
			} else if pr.cipherSuite != "" {
				result.CipherSuites[pr.name] = []string{pr.cipherSuite}
			}
			if pr.alpnProto != "" {
				result.ALPNProtocols[pr.name] = pr.alpnProto
			}
			if pr.curveName != "" {
				result.NegotiatedCurves[pr.name] = pr.curveName
			}
			if pr.cert != nil && result.Certificate == nil {
				result.Certificate = pr.cert
			}
		} else if pr.supported && pr.err != nil {
			anySuccess = true
			lastErrors = append(lastErrors, pr.err)
		} else if pr.err != nil {
			lastErrors = append(lastErrors, pr.err)
		}
	}

	if result.SupportsTLS13 && ctx.Err() == nil {
		if strings.Contains(result.NegotiatedCurves["TLS 1.3"], "MLKEM") {
			result.MLKEMSupported = true
		} else {
			result.MLKEMSupported = c.probeMLKEM(ctx, addr, host)
		}
	}

	result.CheckDuration = time.Since(start)

	if !anySuccess {
		result.FailureReason = classifyFailure(lastErrors)
		if result.FailureReason == FailureReasonNoTLS && c.probeHTTP(ctx, addr, host) {
			result.FailureReason = FailureReasonPlaintextHTTP
			return result, fmt.Errorf("endpoint %s is serving plaintext HTTP without TLS", addr)
		}
		return result, fmt.Errorf("could not establish TLS connection to %s on any TLS version", addr)
	}

	if len(lastErrors) > 0 && classifyFailure(lastErrors) == FailureReasonMutualTLSRequired {
		result.FailureReason = FailureReasonMutualTLSRequired
		return result, fmt.Errorf("endpoint %s requires mutual TLS (client certificate)", addr)
	}

	return result, nil
}

// TLS alert codes for mTLS detection.
const (
	alertBadCertificate      tls.AlertError = 42
	alertCertificateRequired tls.AlertError = 116
)

// classifyFailure analyzes TLS connection errors to determine the failure category.
// Priority order: mTLS > NoTLS > Closed > Timeout > Filtered > Unreachable.
func classifyFailure(errs []error) FailureReason {
	if len(errs) == 0 {
		return FailureReasonUnreachable
	}

	var hasNoTLS, hasMTLS, hasTimeout, hasClosed bool

	for _, err := range errs {
		if isMTLSError(err) {
			hasMTLS = true
		}

		var recordErr tls.RecordHeaderError
		if errors.As(err, &recordErr) {
			hasNoTLS = true
		}

		if errors.Is(err, syscall.ECONNREFUSED) {
			hasClosed = true
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			hasTimeout = true
		}
	}

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
		return FailureReasonTimeout
	}

	return FailureReasonUnreachable
}

func isMTLSError(err error) bool {
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return alertErr == alertBadCertificate || alertErr == alertCertificateRequired
	}
	return false
}

// tryTLSVersion attempts to connect with a specific TLS version
func (c *TLSChecker) tryTLSVersion(ctx context.Context, addr, serverName string, version uint16) (supported bool, cipherSuiteID uint16, cipherSuite string, curveName string, alpnProto string, cert *CertificateDetails, err error) {
	dialer := &net.Dialer{
		Timeout: c.Timeout,
	}

	tlsConfig := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true, //nolint:gosec // We report cert info but don't enforce trust
		ServerName:         serverName,
		NextProtos:         DefaultALPNProtos,
	}
	if c.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*c.ClientCert}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		// mTLS: server requires a client certificate but we proved it speaks this TLS version
		if isMTLSError(err) {
			return true, 0, "", "", "", nil, err
		}
		return false, 0, "", "", "", nil, err
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
		certDetails = ParseCertificate(state.PeerCertificates[0], serverName)
		certDetails.ChainLength = len(state.PeerCertificates)
	}

	return true, state.CipherSuite, cipherSuiteName, curve, state.NegotiatedProtocol, certDetails, nil
}

func (c *TLSChecker) enumerateCiphers(ctx context.Context, addr, serverName string, version, firstCipherID uint16) []string {
	allSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	discovered := []string{tls.CipherSuiteName(firstCipherID)}
	seenIDs := map[uint16]bool{firstCipherID: true}
	dialer := &net.Dialer{Timeout: c.Timeout}

	for {
		select {
		case <-ctx.Done():
			return discovered
		default:
		}

		var remaining []uint16
		for _, cs := range allSuites {
			if !seenIDs[cs.ID] {
				remaining = append(remaining, cs.ID)
			}
		}
		if len(remaining) == 0 {
			break
		}

		tlsConfig := &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: true, //nolint:gosec // We probe capabilities, not trust
			ServerName:         serverName,
			CipherSuites:       remaining,
		}
		if c.ClientCert != nil {
			tlsConfig.Certificates = []tls.Certificate{*c.ClientCert}
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			break
		}

		state := conn.ConnectionState()
		conn.Close() //nolint:errcheck

		if seenIDs[state.CipherSuite] {
			break
		}
		seenIDs[state.CipherSuite] = true
		discovered = append(discovered, tls.CipherSuiteName(state.CipherSuite))
	}

	return discovered
}

// probeMLKEM performs a TLS 1.3 handshake offering only hybrid ML-KEM key
// exchange curves to determine whether the server supports post-quantum key
// exchange. Tests X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024.
func (c *TLSChecker) probeMLKEM(ctx context.Context, addr, serverName string) bool {
	dialer := &net.Dialer{
		Timeout: c.Timeout,
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
		},
		InsecureSkipVerify: true, //nolint:gosec // We probe capabilities, not trust
		ServerName:         serverName,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return false
	}
	conn.Close() //nolint:errcheck

	return true
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
