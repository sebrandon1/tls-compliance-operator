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

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// starttlsserver is the server side of the fixtures used by the e2e tests: it
// speaks a protocol's cleartext prelude and then upgrades the connection to
// TLS. The client-side counterparts live in pkg/tlscheck/starttls.go.

// starttlsPreludeDeadline bounds the cleartext exchange so a probe that never
// completes a handshake cannot leave a goroutine blocked forever.
const starttlsPreludeDeadline = 30 * time.Second

// serveSTARTTLS accepts connections on addr, runs the named protocol's
// cleartext prelude, then serves TLS using tlsCfg.
func serveSTARTTLS(addr, protocol string, tlsCfg *tls.Config) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleSTARTTLSConn(conn, protocol, tlsCfg)
	}
}

func handleSTARTTLSConn(conn net.Conn, protocol string, tlsCfg *tls.Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(starttlsPreludeDeadline))

	if err := servePrelude(conn, protocol); err != nil {
		log.Printf("%s prelude failed: %v", protocol, err)
		return
	}

	_ = conn.SetDeadline(time.Now().Add(starttlsPreludeDeadline))
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("%s TLS handshake failed: %v", protocol, err)
	}
}

func servePrelude(conn net.Conn, protocol string) error {
	switch protocol {
	case "mysql":
		return preludeMySQL(conn)
	case "smtp":
		return preludeSMTP(conn)
	case "imap":
		return preludeIMAP(conn)
	case "pop3":
		return preludePOP3(conn)
	case "lmtp":
		return preludeLMTP(conn)
	case "nntp":
		return preludeNNTP(conn)
	case "sieve":
		return preludeSieve(conn)
	case "ftp":
		return preludeFTP(conn)
	case "xmpp":
		return preludeXMPP(conn)
	default:
		return fmt.Errorf("unsupported STARTTLS protocol %q", protocol)
	}
}

func readLine(r *bufio.Reader) (string, error) {
	return r.ReadString('\n')
}

// preludeMySQL sends a protocol-10 handshake packet and consumes the client's
// 36-byte SSLRequest; MySQL starts TLS immediately afterwards.
func preludeMySQL(conn net.Conn) error {
	payload := []byte{0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	header := []byte{byte(len(payload)), 0, 0, 0}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}

	request := make([]byte, 4+32)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(request[4:8])&0x0800 == 0 {
		return fmt.Errorf("client did not request CLIENT_SSL")
	}
	return nil
}

func preludeSMTP(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "220 test.example.com ESMTP\r\n"); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if _, err := readLine(r); err != nil { // EHLO
		return err
	}
	if _, err := fmt.Fprintf(conn, "250-test.example.com\r\n250-STARTTLS\r\n250 OK\r\n"); err != nil {
		return err
	}
	if _, err := readLine(r); err != nil { // STARTTLS
		return err
	}
	_, err := fmt.Fprintf(conn, "220 Go ahead\r\n")
	return err
}

func preludeIMAP(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "* OK IMAP4rev1 Service Ready\r\n"); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if _, err := readLine(r); err != nil { // STARTTLS
		return err
	}
	_, err := fmt.Fprintf(conn, "a001 OK Begin TLS negotiation\r\n")
	return err
}

func preludePOP3(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "+OK POP3 ready\r\n"); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if _, err := readLine(r); err != nil { // STLS
		return err
	}
	_, err := fmt.Fprintf(conn, "+OK Begin TLS negotiation\r\n")
	return err
}

func preludeLMTP(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "220 test.example.com LMTP\r\n"); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if _, err := readLine(r); err != nil { // LHLO
		return err
	}
	if _, err := fmt.Fprintf(conn, "250-test.example.com\r\n250-STARTTLS\r\n250 OK\r\n"); err != nil {
		return err
	}
	if _, err := readLine(r); err != nil { // STARTTLS
		return err
	}
	_, err := fmt.Fprintf(conn, "220 Go ahead\r\n")
	return err
}

func preludeNNTP(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "200 NNTP ready\r\n"); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if _, err := readLine(r); err != nil { // STARTTLS
		return err
	}
	_, err := fmt.Fprintf(conn, "382 Continue with TLS\r\n")
	return err
}

func preludeSieve(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "OK Sieve ready\r\n"); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if _, err := readLine(r); err != nil { // STARTTLS
		return err
	}
	_, err := fmt.Fprintf(conn, "OK Begin TLS negotiation\r\n")
	return err
}

func preludeFTP(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "220 FTP ready\r\n"); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if _, err := readLine(r); err != nil { // AUTH TLS
		return err
	}
	_, err := fmt.Fprintf(conn, "234 Proceed with negotiation\r\n")
	return err
}

func preludeXMPP(conn net.Conn) error {
	r := bufio.NewReader(conn)
	if err := readUntil(r, ">"); err != nil { // stream header
		return err
	}
	if _, err := fmt.Fprintf(conn, "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"+
		"</stream:features>"); err != nil {
		return err
	}
	if err := readUntil(r, ">"); err != nil { // starttls request
		return err
	}
	_, err := fmt.Fprintf(conn, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	return err
}

func readUntil(r *bufio.Reader, want string) error {
	var seen strings.Builder
	for seen.Len() < 8192 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		seen.WriteByte(b)
		if strings.Contains(seen.String(), want) {
			return nil
		}
	}
	return fmt.Errorf("%q not found", want)
}
