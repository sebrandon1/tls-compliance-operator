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
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

type starttlsProtocol int

const (
	starttlsProtocolSMTP     starttlsProtocol = iota
	starttlsProtocolIMAP
	starttlsProtocolLDAP
	starttlsProtocolPostgres
)

// defaultSTARTTLSPorts maps well-known STARTTLS port numbers to their protocol.
var defaultSTARTTLSPorts = map[int]starttlsProtocol{
	25:   starttlsProtocolSMTP,
	587:  starttlsProtocolSMTP,
	143:  starttlsProtocolIMAP,
	389:  starttlsProtocolLDAP,
	5432: starttlsProtocolPostgres,
}

// resolveSTARTTLS returns the STARTTLS protocol for a port, checking
// any test-injected override before falling back to the built-in map.
func (c *TLSChecker) resolveSTARTTLS(port int) (starttlsProtocol, bool) {
	if proto, ok := c.starttlsOverride[port]; ok {
		return proto, ok
	}
	proto, ok := defaultSTARTTLSPorts[port]
	return proto, ok
}

// upgradeSTARTTLS performs the cleartext portion of the STARTTLS handshake on
// conn. The deadline must be set by the caller before invoking this function.
func upgradeSTARTTLS(conn net.Conn, proto starttlsProtocol) error {
	switch proto {
	case starttlsProtocolSMTP:
		return upgradeSMTP(conn)
	case starttlsProtocolIMAP:
		return upgradeIMAP(conn)
	case starttlsProtocolLDAP:
		return upgradeLDAP(conn)
	case starttlsProtocolPostgres:
		return upgradePostgres(conn)
	default:
		return fmt.Errorf("starttls: unknown protocol %d", proto)
	}
}

func upgradeSMTP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	if err := expectSMTP220(r); err != nil {
		return fmt.Errorf("smtp: greeting: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "EHLO localhost\r\n"); err != nil {
		return fmt.Errorf("smtp: ehlo write: %w", err)
	}
	if err := expectSMTPSTARTTLSCap(r); err != nil {
		return fmt.Errorf("smtp: capability: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("smtp: starttls write: %w", err)
	}
	if err := expectSMTP220(r); err != nil {
		return fmt.Errorf("smtp: starttls response: %w", err)
	}
	return nil
}

// expectSMTP220 reads lines until it finds the terminating "220 " line,
// returning an error if any line has a different code.
func expectSMTP220(r *bufio.Reader) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if len(line) < 4 {
			return fmt.Errorf("short smtp response: %q", line)
		}
		if !strings.HasPrefix(line, "220") {
			return fmt.Errorf("unexpected smtp response: %q (want 220)", line)
		}
		if line[3] == ' ' {
			return nil
		}
	}
}

// expectSMTPSTARTTLSCap reads a multi-line EHLO response and returns an error
// if STARTTLS is not listed as a capability.
func expectSMTPSTARTTLSCap(r *bufio.Reader) error {
	hasSTARTTLS := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if len(line) < 4 {
			return fmt.Errorf("short smtp ehlo line: %q", line)
		}
		if !strings.HasPrefix(line, "250") {
			return fmt.Errorf("unexpected smtp ehlo response: %q", line)
		}
		if strings.EqualFold(strings.TrimSpace(line[4:]), "STARTTLS") {
			hasSTARTTLS = true
		}
		if line[3] == ' ' {
			break
		}
	}
	if !hasSTARTTLS {
		return errors.New("smtp: server did not advertise STARTTLS")
	}
	return nil
}

func upgradeIMAP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("imap: greeting: %w", err)
	}
	if !strings.HasPrefix(line, "* OK") {
		return fmt.Errorf("imap: unexpected greeting: %q", line)
	}
	if _, err := fmt.Fprintf(conn, "a001 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("imap: starttls write: %w", err)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("imap: starttls response: %w", err)
	}
	if !strings.HasPrefix(line, "a001 OK") {
		return fmt.Errorf("imap: starttls refused: %q", line)
	}
	return nil
}

// ldapStartTLSRequest is a DER-encoded LDAP ExtendedRequest for StartTLS
// (OID 1.3.6.1.4.1.1466.20037) with messageID 1.
var ldapStartTLSRequest = []byte{
	0x30, 0x1d, // SEQUENCE (LDAPMessage), 29 bytes
	0x02, 0x01, 0x01, // INTEGER 1 (messageID)
	0x77, 0x18, // [APPLICATION 23] (extendedReq), 24 bytes
	0x80, 0x16, // [0] IMPLICIT (requestName), 22 bytes
	// "1.3.6.1.4.1.1466.20037"
	0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e,
	0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36,
	0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
}

func upgradeLDAP(conn net.Conn) error {
	if _, err := conn.Write(ldapStartTLSRequest); err != nil {
		return fmt.Errorf("ldap: write request: %w", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("ldap: read response: %w", err)
	}
	// Scan for ENUMERATED resultCode = 0 (0x0a 0x01 0x00).
	if !ldapResultSuccess(buf[:n]) {
		return errors.New("ldap: starttls refused or non-zero result code")
	}
	return nil
}

// ldapResultSuccess returns true if buf contains an ENUMERATED value 0,
// which indicates a successful LDAP StartTLS ExtendedResponse.
func ldapResultSuccess(buf []byte) bool {
	for i := 0; i < len(buf)-2; i++ {
		if buf[i] == 0x0a && buf[i+1] == 0x01 && buf[i+2] == 0x00 {
			return true
		}
	}
	return false
}

func upgradePostgres(conn net.Conn) error {
	// SSLRequest: total length (4 bytes) + magic number (4 bytes).
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], 80877103)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("postgres: write SSLRequest: %w", err)
	}
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("postgres: read response: %w", err)
	}
	if resp[0] != 'S' {
		return fmt.Errorf("postgres: ssl not supported (server replied %q)", resp[0])
	}
	return nil
}

// trySTARTTLSVersion dials addr, performs the STARTTLS upgrade for proto, then
// completes a TLS handshake pinned to version. It mirrors tryTLSVersion.
func (c *TLSChecker) trySTARTTLSVersion(
	ctx context.Context, addr, host string, proto starttlsProtocol, version uint16,
) (supported bool, cipherID uint16, cipherSuite, curveName, alpnProto string, cert *CertificateDetails, err error) {
	dialer := &net.Dialer{Timeout: c.Timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, 0, "", "", "", nil, err
	}

	deadline := time.Now().Add(c.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = rawConn.SetDeadline(deadline)

	if err := upgradeSTARTTLS(rawConn, proto); err != nil {
		_ = rawConn.Close()
		return false, 0, "", "", "", nil, err
	}

	tlsCfg := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true, //nolint:gosec // probe only; caller asserts compliance, not cert validity
		ServerName:         host,
		NextProtos:         DefaultALPNProtos,
	}
	if c.ClientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*c.ClientCert}
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if isMTLSError(err) {
			return true, 0, "", "", "", nil, err
		}
		return false, 0, "", "", "", nil, err
	}

	state := tlsConn.ConnectionState()
	cipherSuiteName := tls.CipherSuiteName(state.CipherSuite)
	var curve string
	if state.CurveID != 0 {
		curve = state.CurveID.String()
	}
	var certDetails *CertificateDetails
	if len(state.PeerCertificates) > 0 {
		certDetails = ParseCertificate(state.PeerCertificates[0], host)
		certDetails.ChainLength = len(state.PeerCertificates)
	}
	return true, state.CipherSuite, cipherSuiteName, curve, state.NegotiatedProtocol, certDetails, nil
}

// probeSTARTTLS runs TLS version probes concurrently over STARTTLS-upgraded connections.
// Returns a populated TLSCheckResult on any success, nil if all probes fail.
func (c *TLSChecker) probeSTARTTLS(ctx context.Context, addr, host string, proto starttlsProtocol) *TLSCheckResult {
	probeResults := make([]versionProbeResult, len(tlsVersionInfo))
	g, gctx := errgroup.WithContext(ctx)
	for i, vi := range tlsVersionInfo {
		g.Go(func() error {
			pr := &probeResults[i]
			pr.supported, _, pr.cipherSuite, pr.curveName, pr.alpnProto, pr.cert, pr.err = c.trySTARTTLSVersion(gctx, addr, host, proto, vi.version)
			return nil
		})
	}
	_ = g.Wait()

	result := &TLSCheckResult{
		CipherSuites:     make(map[string][]string),
		ALPNProtocols:    make(map[string]string),
		NegotiatedCurves: make(map[string]string),
	}
	anySuccess := false
	for i, vi := range tlsVersionInfo {
		pr := &probeResults[i]
		vi.field(result, pr.supported)
		if pr.supported && pr.err == nil {
			anySuccess = true
			if pr.cipherSuite != "" {
				result.CipherSuites[vi.name] = []string{pr.cipherSuite}
			}
			if pr.alpnProto != "" {
				result.ALPNProtocols[vi.name] = pr.alpnProto
			}
			if pr.curveName != "" {
				result.NegotiatedCurves[vi.name] = pr.curveName
			}
			if pr.cert != nil && result.Certificate == nil {
				result.Certificate = pr.cert
			}
		}
	}
	if !anySuccess {
		return nil
	}
	return result
}
