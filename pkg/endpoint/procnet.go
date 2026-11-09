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
