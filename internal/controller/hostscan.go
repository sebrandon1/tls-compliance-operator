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

package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/endpoint"
)

// defaultProcNetDir is where the host's socket tables are mounted. With
// hostPID, the pod's /proc/net is the node's.
const defaultProcNetDir = "/proc/net"

// scanHostEndpoints reads the node's LISTEN sockets and scans the ones inside
// the configured port range at 127.0.0.1. It requires hostPID and is a no-op
// unless --scan-host-ports is set.
func (r *EndpointReconciler) scanHostEndpoints(ctx context.Context) error {
	if r.HostScanPorts == nil {
		return nil
	}
	logger := log.FromContext(ctx)

	ports, err := readHostListeners(r.procNetDir())
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "node"
	}

	for _, port := range r.HostScanPorts.Filter(ports) {
		ep := endpoint.Endpoint{
			Host:            "127.0.0.1",
			Port:            port,
			SourceKind:      securityv1alpha1.SourceKindHost,
			SourceNamespace: "host",
			SourceName:      hostname,
		}
		if err := r.processEndpoint(ctx, &ep); err != nil {
			logger.Error(err, "failed to process host endpoint", "port", port)
		}
	}
	return nil
}

// procNetDir returns the directory holding the socket tables.
func (r *EndpointReconciler) procNetDir() string {
	if r.ProcNetDir != "" {
		return r.ProcNetDir
	}
	return defaultProcNetDir
}

// readHostListeners returns the LISTEN ports from the IPv4 and IPv6 socket
// tables, deduplicated. A missing IPv6 table is not an error.
func readHostListeners(dir string) ([]int32, error) {
	content, err := os.ReadFile(filepath.Join(dir, "tcp"))
	if err != nil {
		return nil, fmt.Errorf("read host socket table: %w", err)
	}
	ports := endpoint.ParseProcNetTCP(string(content))

	if v6, err := os.ReadFile(filepath.Join(dir, "tcp6")); err == nil {
		seen := make(map[int32]bool, len(ports))
		for _, port := range ports {
			seen[port] = true
		}
		for _, port := range endpoint.ParseProcNetTCP(string(v6)) {
			if !seen[port] {
				ports = append(ports, port)
			}
		}
	}
	return ports, nil
}
