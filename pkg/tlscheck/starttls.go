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
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
)

type starttlsProtocol int

const (
	starttlsProtocolSMTP starttlsProtocol = iota
	starttlsProtocolIMAP
	starttlsProtocolLDAP
	starttlsProtocolPostgres
	starttlsProtocolMySQL
	starttlsProtocolPOP3
	starttlsProtocolLMTP
	starttlsProtocolXMPP
	starttlsProtocolXMPPServer
	starttlsProtocolNNTP
	starttlsProtocolSieve
	starttlsProtocolFTP
)

// starttlsProtocolNames maps the --starttls-ports protocol names to their
// implementation.
var starttlsProtocolNames = map[string]starttlsProtocol{
	"smtp":        starttlsProtocolSMTP,
	"imap":        starttlsProtocolIMAP,
	"ldap":        starttlsProtocolLDAP,
	"postgres":    starttlsProtocolPostgres,
	"mysql":       starttlsProtocolMySQL,
	"pop3":        starttlsProtocolPOP3,
	"lmtp":        starttlsProtocolLMTP,
	"xmpp":        starttlsProtocolXMPP,
	"xmpp-server": starttlsProtocolXMPPServer,
	"nntp":        starttlsProtocolNNTP,
	"sieve":       starttlsProtocolSieve,
	"ftp":         starttlsProtocolFTP,
}

// defaultSTARTTLSPorts maps well-known STARTTLS port numbers to their protocol.
var defaultSTARTTLSPorts = map[int]starttlsProtocol{
	21:   starttlsProtocolFTP,
	24:   starttlsProtocolLMTP,
	25:   starttlsProtocolSMTP,
	110:  starttlsProtocolPOP3,
	119:  starttlsProtocolNNTP,
	143:  starttlsProtocolIMAP,
	389:  starttlsProtocolLDAP,
	587:  starttlsProtocolSMTP,
	3306: starttlsProtocolMySQL,
	3307: starttlsProtocolMySQL,
	4190: starttlsProtocolSieve,
	5222: starttlsProtocolXMPP,
	5269: starttlsProtocolXMPPServer,
	5432: starttlsProtocolPostgres,
}

// ParseSTARTTLSPorts parses a --starttls-ports value of the form
// "proto=port[:port][,proto=port...]". An entry with the same port appearing
// later overrides an earlier one.
func ParseSTARTTLSPorts(spec string) (map[int]string, error) {
	overrides := make(map[int]string)
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		name, ports, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("invalid --starttls-ports entry %q: want proto=port[:port]", entry)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if _, ok := starttlsProtocolNames[name]; !ok {
			return nil, fmt.Errorf("unknown STARTTLS protocol %q", name)
		}

		for _, rawPort := range strings.Split(ports, ":") {
			port, err := strconv.Atoi(strings.TrimSpace(rawPort))
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port %q in --starttls-ports entry %q", rawPort, entry)
			}
			overrides[port] = name
		}
	}
	if len(overrides) == 0 {
		return nil, errors.New("--starttls-ports contains no port mappings")
	}
	return overrides, nil
}

// resolveSTARTTLS returns the STARTTLS protocol for a port, checking
// any test-injected override before falling back to the built-in map.
func (c *TLSChecker) resolveSTARTTLS(port int) (starttlsProtocol, bool) {
	if proto, ok := c.starttlsOverride[port]; ok {
		return proto, ok
	}
	if name, ok := c.STARTTLSPorts[port]; ok {
		if proto, ok := starttlsProtocolNames[name]; ok {
			return proto, true
		}
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
	case starttlsProtocolMySQL:
		return upgradeMySQL(conn)
	case starttlsProtocolPOP3:
		return upgradePOP3(conn)
	case starttlsProtocolLMTP:
		return upgradeLMTP(conn)
	case starttlsProtocolXMPP, starttlsProtocolXMPPServer:
		return upgradeXMPP(conn)
	case starttlsProtocolNNTP:
		return upgradeNNTP(conn)
	case starttlsProtocolSieve:
		return upgradeSieve(conn)
	case starttlsProtocolFTP:
		return upgradeFTP(conn)
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
	rawConn, stopCancel, err := c.dialProbe(ctx, addr)
	if err != nil {
		return false, 0, "", "", "", nil, err
	}

	// The close-on-cancel hook only matters for the plaintext upgrade's blocking
	// reads; the TLS handshake below honors ctx on its own.
	upgradeErr := upgradeSTARTTLS(rawConn, proto)
	stopCancel()
	if upgradeErr != nil {
		_ = rawConn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, 0, "", "", "", nil, ctxErr
		}
		return false, 0, "", "", "", nil, upgradeErr
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

// mysqlClientCapabilities requests protocol 4.1, secure connection and plugin
// auth alongside CLIENT_SSL, matching what a modern client sends.
const mysqlClientCapabilities uint32 = 0x0200 | 0x0800 | 0x8000 | 0x00080000

// upgradeMySQL reads the server handshake and replies with an SSLRequest packet
// carrying CLIENT_SSL. MySQL starts TLS immediately after that packet, so a nil
// return means the connection is ready for a TLS handshake.
func upgradeMySQL(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("mysql: read handshake header: %w", err)
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length < 1 || length > 1<<16 {
		return fmt.Errorf("mysql: invalid handshake length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("mysql: read handshake payload: %w", err)
	}
	if payload[0] != 0x0a {
		return fmt.Errorf("mysql: unexpected handshake protocol version %d", payload[0])
	}

	// SSLRequest: 4-byte packet header (32-byte payload, sequence 1) followed by
	// capability flags, max packet size, charset and 23 reserved bytes.
	request := make([]byte, 4+32)
	request[0] = 32
	request[3] = 1
	binary.LittleEndian.PutUint32(request[4:8], mysqlClientCapabilities)
	binary.LittleEndian.PutUint32(request[8:12], 1<<24)
	request[12] = 0x21 // utf8_general_ci
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("mysql: write SSLRequest: %w", err)
	}
	return nil
}

func upgradePOP3(conn net.Conn) error {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3: greeting: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(line), "+OK") {
		return fmt.Errorf("pop3: unexpected greeting: %q", line)
	}
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return fmt.Errorf("pop3: stls write: %w", err)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3: stls response: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(line), "+OK") {
		return fmt.Errorf("pop3: stls refused: %q", line)
	}
	return nil
}

// upgradeLMTP mirrors SMTP: LHLO advertises STARTTLS the same way EHLO does.
func upgradeLMTP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	if err := expectSMTP220(r); err != nil {
		return fmt.Errorf("lmtp: greeting: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "LHLO localhost\r\n"); err != nil {
		return fmt.Errorf("lmtp: lhlo write: %w", err)
	}
	if err := expectSMTPSTARTTLSCap(r); err != nil {
		return fmt.Errorf("lmtp: capability: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("lmtp: starttls write: %w", err)
	}
	if err := expectSMTP220(r); err != nil {
		return fmt.Errorf("lmtp: starttls response: %w", err)
	}
	return nil
}

// upgradeXMPP negotiates STARTTLS by opening a stream and waiting for the
// server to advertise <starttls> before requesting it.
func upgradeXMPP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	if _, err := fmt.Fprintf(conn,
		"<stream:stream to='localhost' xmlns='jabber:client' "+
			"xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"); err != nil {
		return fmt.Errorf("xmpp: stream write: %w", err)
	}
	if err := readUntil(r, "<starttls", 8192); err != nil {
		return fmt.Errorf("xmpp: starttls not advertised: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"); err != nil {
		return fmt.Errorf("xmpp: starttls write: %w", err)
	}
	if err := readUntil(r, "<proceed", 8192); err != nil {
		return fmt.Errorf("xmpp: starttls refused: %w", err)
	}
	return nil
}

// readUntil consumes bytes until want appears, failing after limit bytes.
func readUntil(r *bufio.Reader, want string, limit int) error {
	read := 0
	var seen strings.Builder
	for read < limit {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		read++
		seen.WriteByte(b)
		if strings.Contains(seen.String(), want) {
			return nil
		}
	}
	return fmt.Errorf("%q not found within %d bytes", want, limit)
}

func upgradeNNTP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("nntp: greeting: %w", err)
	}
	if !strings.HasPrefix(line, "200") && !strings.HasPrefix(line, "201") {
		return fmt.Errorf("nntp: unexpected greeting: %q", line)
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("nntp: starttls write: %w", err)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("nntp: starttls response: %w", err)
	}
	if !strings.HasPrefix(line, "382") {
		return fmt.Errorf("nntp: starttls refused: %q", line)
	}
	return nil
}

func upgradeSieve(conn net.Conn) error {
	r := bufio.NewReader(conn)
	// The greeting is one or more capability lines ending with "OK".
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("sieve: greeting: %w", err)
		}
		if strings.HasPrefix(strings.ToUpper(line), "OK") {
			break
		}
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("sieve: starttls write: %w", err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("sieve: starttls response: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(line), "OK") {
		return fmt.Errorf("sieve: starttls refused: %q", line)
	}
	return nil
}

func upgradeFTP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("ftp: greeting: %w", err)
	}
	if !strings.HasPrefix(line, "220") {
		return fmt.Errorf("ftp: unexpected greeting: %q", line)
	}
	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return fmt.Errorf("ftp: auth tls write: %w", err)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("ftp: auth tls response: %w", err)
	}
	if !strings.HasPrefix(line, "234") {
		return fmt.Errorf("ftp: AUTH TLS refused: %q", line)
	}
	return nil
}
