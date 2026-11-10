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

package endpoint

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ProcNetReader reads the combined contents of /proc/net/tcp and
// /proc/net/tcp6 from a container.
type ProcNetReader interface {
	ReadProcNet(ctx context.Context, namespace, pod, container string) (string, error)
}

// procNetListenState is the hex socket state for LISTEN in /proc/net/tcp{,6}.
const procNetListenState = "0A"

// PortRange is an inclusive host port range.
type PortRange struct {
	Start int32
	End   int32
}

// ParsePortRange parses "<start>-<end>". Both bounds must be 1-65535 and
// start must not exceed end.
func ParsePortRange(value string) (PortRange, error) {
	startStr, endStr, ok := strings.Cut(value, "-")
	if !ok {
		return PortRange{}, fmt.Errorf("port range %q must be <start>-<end>", value)
	}
	start, err := parsePortBound(startStr)
	if err != nil {
		return PortRange{}, fmt.Errorf("port range %q: start: %w", value, err)
	}
	end, err := parsePortBound(endStr)
	if err != nil {
		return PortRange{}, fmt.Errorf("port range %q: end: %w", value, err)
	}
	if start > end {
		return PortRange{}, fmt.Errorf("port range %q: start %d is greater than end %d", value, start, end)
	}
	return PortRange{Start: start, End: end}, nil
}

// parsePortBound parses one inclusive bound.
func parsePortBound(value string) (int32, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d outside 1-65535", port)
	}
	return int32(port), nil
}

// Contains reports whether port is inside the range.
func (r PortRange) Contains(port int32) bool {
	return port >= r.Start && port <= r.End
}

// Filter returns the ports inside the range, preserving order.
func (r PortRange) Filter(ports []int32) []int32 {
	filtered := make([]int32, 0, len(ports))
	for _, port := range ports {
		if r.Contains(port) {
			filtered = append(filtered, port)
		}
	}
	return filtered
}

// ProcNetListener is one LISTEN socket from /proc/net/tcp or /proc/net/tcp6.
type ProcNetListener struct {
	Port    int32
	Address net.IP
}

// ParseProcNetListeners returns every LISTEN socket (port and bind address)
// from the contents of /proc/net/tcp and /proc/net/tcp6. Entries are
// deduplicated by port and address and sorted by port, then address. Malformed
// rows and rows whose address cannot be decoded are skipped.
func ParseProcNetListeners(content string) []ProcNetListener {
	seen := make(map[string]bool)
	listeners := make([]ProcNetListener, 0)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		// sl local_address rem_address st ... — the header has fewer columns
		// and state is not hex.
		if len(fields) < 4 || fields[3] != procNetListenState {
			continue
		}
		listener, ok := parseProcNetLocalAddr(fields[1])
		if !ok {
			continue
		}
		key := fmt.Sprintf("%d|%s", listener.Port, listener.Address)
		if seen[key] {
			continue
		}
		seen[key] = true
		listeners = append(listeners, listener)
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		return listeners[i].Address.String() < listeners[j].Address.String()
	})
	return listeners
}

// parseProcNetLocalAddr parses a local_address field ("ADDR:PORT", both hex).
func parseProcNetLocalAddr(localAddress string) (ProcNetListener, bool) {
	addrHex, portHex, ok := strings.Cut(localAddress, ":")
	if !ok {
		return ProcNetListener{}, false
	}
	value, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || value == 0 {
		return ProcNetListener{}, false
	}
	address, ok := decodeProcNetAddr(addrHex)
	if !ok {
		return ProcNetListener{}, false
	}
	return ProcNetListener{Port: int32(value), Address: address}, true
}

// decodeProcNetAddr decodes a /proc/net/tcp local address. IPv4 addresses are
// 8 hex characters and IPv6 addresses are 32; both are stored little-endian
// (IPv6 as four little-endian 32-bit words).
func decodeProcNetAddr(addrHex string) (net.IP, bool) {
	switch len(addrHex) {
	case 8:
		raw, err := hex.DecodeString(addrHex)
		if err != nil {
			return nil, false
		}
		return net.IP{raw[3], raw[2], raw[1], raw[0]}, true
	case 32:
		raw, err := hex.DecodeString(addrHex)
		if err != nil {
			return nil, false
		}
		for i := 0; i < len(raw); i += 4 {
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		return net.IP(raw), true
	default:
		return nil, false
	}
}

// IsLoopbackOnly reports whether every address in addrs is a loopback address.
// An empty list means the bind address is unknown, so it is not loopback-only.
// Unparseable addresses make the result false rather than guessing.
func IsLoopbackOnly(addrs []string) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, raw := range addrs {
		ip := net.ParseIP(raw)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// ParseProcNetTCP returns the local ports in LISTEN state from the contents of
// /proc/net/tcp or /proc/net/tcp6. Ports are deduplicated and sorted ascending.
// Malformed lines are skipped.
func ParseProcNetTCP(content string) []int32 {
	seen := make(map[int32]bool)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		// sl local_address rem_address st ... — the header has fewer columns
		// and state is not hex.
		if len(fields) < 4 || fields[3] != procNetListenState {
			continue
		}
		port, ok := procNetLocalPort(fields[1])
		if !ok {
			continue
		}
		seen[port] = true
	}
	ports := make([]int32, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

// procNetLocalPort extracts the port from a /proc/net/tcp local_address
// (hex-encoded address and port separated by a colon).
func procNetLocalPort(localAddress string) (int32, bool) {
	_, portHex, ok := strings.Cut(localAddress, ":")
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || value == 0 {
		return 0, false
	}
	return int32(value), true
}
