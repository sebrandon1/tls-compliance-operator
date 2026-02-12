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
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Endpoint represents a TLS endpoint to check
type Endpoint struct {
	Host            string
	Port            int32
	SourceKind      string
	SourceNamespace string
	SourceName      string
}

// MaxCRNameLength is the maximum length for a CR name
const MaxCRNameLength = 63

// sanitizeRegex matches characters not allowed in Kubernetes names
var sanitizeRegex = regexp.MustCompile(`[^a-z0-9-]`)

// ExtractFromService returns TLS endpoints from a Service.
// It looks for ports that are 443, 8443, or named https/https-*.
func ExtractFromService(svc *corev1.Service) []Endpoint {
	var endpoints []Endpoint

	for _, port := range svc.Spec.Ports {
		if isTLSPort(port) {
			host := fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace)
			endpoints = append(endpoints, Endpoint{
				Host:            host,
				Port:            port.Port,
				SourceKind:      "Service",
				SourceNamespace: svc.Namespace,
				SourceName:      svc.Name,
			})
		}
	}

	return endpoints
}

// ExtractFromIngress returns TLS endpoints from an Ingress.
// It extracts hosts from spec.tls[].hosts.
func ExtractFromIngress(ing *networkingv1.Ingress) []Endpoint {
	var endpoints []Endpoint

	for _, tlsBlock := range ing.Spec.TLS {
		for _, host := range tlsBlock.Hosts {
			endpoints = append(endpoints, Endpoint{
				Host:            host,
				Port:            443,
				SourceKind:      "Ingress",
				SourceNamespace: ing.Namespace,
				SourceName:      ing.Name,
			})
		}
	}

	return endpoints
}

// ExtractFromRoute extracts TLS endpoints from an OpenShift Route (unstructured).
// It only includes Routes that have TLS termination configured.
func ExtractFromRoute(obj *unstructured.Unstructured) []Endpoint {
	var endpoints []Endpoint

	// Check if TLS is configured
	tls, found, err := unstructured.NestedMap(obj.Object, "spec", "tls")
	if err != nil || !found || tls == nil {
		return nil
	}

	// Check termination type is set
	termination, _, _ := unstructured.NestedString(obj.Object, "spec", "tls", "termination")
	if termination == "" {
		return nil
	}

	// Get the host
	host, found, err := unstructured.NestedString(obj.Object, "spec", "host")
	if err != nil || !found || host == "" {
		return nil
	}

	endpoints = append(endpoints, Endpoint{
		Host:            host,
		Port:            443,
		SourceKind:      "Route",
		SourceNamespace: obj.GetNamespace(),
		SourceName:      obj.GetName(),
	})

	return endpoints
}

// GenerateCRName creates a deterministic CR name from an endpoint.
// Format: <sanitized-host>-<port>-<8-char-hash>
// The hash is derived from sourceKind/sourceNamespace/sourceName/host/port.
func GenerateCRName(ep Endpoint) string {
	// Generate hash from the full identity
	identity := fmt.Sprintf("%s/%s/%s/%s/%d", ep.SourceKind, ep.SourceNamespace, ep.SourceName, ep.Host, ep.Port)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))[:8]

	// Sanitize host for use in K8s name
	sanitized := strings.ToLower(ep.Host)
	sanitized = strings.ReplaceAll(sanitized, ".", "-")
	sanitized = sanitizeRegex.ReplaceAllString(sanitized, "")

	// Trim trailing hyphens
	sanitized = strings.TrimRight(sanitized, "-")

	// Build name: sanitized-host-port-hash
	name := fmt.Sprintf("%s-%d-%s", sanitized, ep.Port, hash)

	// Ensure the name doesn't exceed K8s limits
	if len(name) > MaxCRNameLength {
		// Truncate the host part to fit
		maxHostLen := MaxCRNameLength - len(fmt.Sprintf("-%d-%s", ep.Port, hash)) - 1
		if maxHostLen < 1 {
			maxHostLen = 1
		}
		sanitized = sanitized[:maxHostLen]
		sanitized = strings.TrimRight(sanitized, "-")
		name = fmt.Sprintf("%s-%d-%s", sanitized, ep.Port, hash)
	}

	return name
}

// isTLSPort checks if a ServicePort is likely a TLS port
func isTLSPort(port corev1.ServicePort) bool {
	// Check well-known TLS ports
	if port.Port == 443 || port.Port == 8443 {
		return true
	}

	// Check port name
	name := strings.ToLower(port.Name)
	if name == "https" || strings.HasPrefix(name, "https-") {
		return true
	}

	return false
}
