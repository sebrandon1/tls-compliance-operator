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
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// Endpoint represents a TLS endpoint to check
type Endpoint struct {
	Host            string
	Port            int32
	SourceKind      securityv1alpha1.SourceKind
	SourceNamespace string
	SourceName      string
	IsProbePort     bool
}

// MaxCRNameLength is the maximum length for a CR name
const MaxCRNameLength = 63

// sanitizeRegex matches characters not allowed in Kubernetes names
var sanitizeRegex = regexp.MustCompile(`[^a-z0-9-]`)

// IsHeadlessService returns true if the service has ClusterIP set to "None".
func IsHeadlessService(svc *corev1.Service) bool {
	return svc.Spec.ClusterIP == corev1.ClusterIPNone
}

// ExtractFromHeadlessService returns TLS endpoints for each address of a
// headless service. Each address × TLS port yields one endpoint.
func ExtractFromHeadlessService(svc *corev1.Service, addresses []string) []Endpoint {
	var endpoints []Endpoint
	for i := range svc.Spec.Ports {
		if !isTLSPort(&svc.Spec.Ports[i]) {
			continue
		}
		for _, addr := range addresses {
			endpoints = append(endpoints, Endpoint{
				Host:            addr,
				Port:            svc.Spec.Ports[i].Port,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: svc.Namespace,
				SourceName:      svc.Name,
			})
		}
	}
	return endpoints
}

// ExtractFromService returns TLS endpoints from a Service.
// It looks for ports that are 443, 8443, or named https/https-*.
// For ExternalName services, the host is spec.externalName and
// port 443 is assumed when no ports are defined.
func ExtractFromService(svc *corev1.Service) []Endpoint {
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return extractFromExternalNameService(svc)
	}

	var endpoints []Endpoint

	for i := range svc.Spec.Ports {
		if isTLSPort(&svc.Spec.Ports[i]) {
			host := fmt.Sprintf("%s.%s", svc.Name, svc.Namespace)
			endpoints = append(endpoints, Endpoint{
				Host:            host,
				Port:            svc.Spec.Ports[i].Port,
				SourceKind:      securityv1alpha1.SourceKindService,
				SourceNamespace: svc.Namespace,
				SourceName:      svc.Name,
			})
		}
	}

	return endpoints
}

func extractFromExternalNameService(svc *corev1.Service) []Endpoint {
	host := svc.Spec.ExternalName
	if host == "" {
		return nil
	}

	var endpoints []Endpoint

	if len(svc.Spec.Ports) == 0 {
		endpoints = append(endpoints, Endpoint{
			Host:            host,
			Port:            443,
			SourceKind:      securityv1alpha1.SourceKindService,
			SourceNamespace: svc.Namespace,
			SourceName:      svc.Name,
		})
	} else {
		for i := range svc.Spec.Ports {
			if isTLSPort(&svc.Spec.Ports[i]) {
				endpoints = append(endpoints, Endpoint{
					Host:            host,
					Port:            svc.Spec.Ports[i].Port,
					SourceKind:      securityv1alpha1.SourceKindService,
					SourceNamespace: svc.Namespace,
					SourceName:      svc.Name,
				})
			}
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
				SourceKind:      securityv1alpha1.SourceKindIngress,
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
		SourceKind:      securityv1alpha1.SourceKindRoute,
		SourceNamespace: obj.GetNamespace(),
		SourceName:      obj.GetName(),
	})

	return endpoints
}

// ExtractFromHTTPRoute extracts TLS endpoints from a Gateway API HTTPRoute (unstructured).
func ExtractFromHTTPRoute(obj *unstructured.Unstructured) []Endpoint {
	hostnames, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "hostnames")
	if len(hostnames) == 0 {
		return nil
	}
	var endpoints []Endpoint
	for _, host := range hostnames {
		endpoints = append(endpoints, Endpoint{
			Host: host, Port: 443, SourceKind: securityv1alpha1.SourceKindHTTPRoute,
			SourceNamespace: obj.GetNamespace(), SourceName: obj.GetName(),
		})
	}
	return endpoints
}

// ExtractFromTLSRoute extracts TLS endpoints from a Gateway API TLSRoute (unstructured).
func ExtractFromTLSRoute(obj *unstructured.Unstructured) []Endpoint {
	hostnames, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "hostnames")
	if len(hostnames) == 0 {
		return nil
	}
	var endpoints []Endpoint
	for _, host := range hostnames {
		endpoints = append(endpoints, Endpoint{
			Host: host, Port: 443, SourceKind: securityv1alpha1.SourceKindTLSRoute,
			SourceNamespace: obj.GetNamespace(), SourceName: obj.GetName(),
		})
	}
	return endpoints
}

// ExtractFromGateway extracts TLS endpoints from a Gateway API Gateway (unstructured).
func ExtractFromGateway(obj *unstructured.Unstructured) []Endpoint {
	listeners, _, _ := unstructured.NestedSlice(obj.Object, "spec", "listeners")
	if len(listeners) == 0 {
		return nil
	}
	addresses, _, _ := unstructured.NestedSlice(obj.Object, "status", "addresses")
	host := ""
	for _, addr := range addresses {
		if m, ok := addr.(map[string]interface{}); ok {
			if v, ok := m["value"].(string); ok && v != "" {
				host = v
				break
			}
		}
	}
	if host == "" {
		host = obj.GetName()
	}
	var endpoints []Endpoint
	for _, l := range listeners {
		listener, ok := l.(map[string]interface{})
		if !ok {
			continue
		}
		protocol, _, _ := unstructured.NestedString(listener, "protocol")
		if protocol != "HTTPS" && protocol != "TLS" {
			continue
		}
		port, found, _ := unstructured.NestedInt64(listener, "port")
		if !found || port < 1 || port > 65535 {
			continue
		}
		endpoints = append(endpoints, Endpoint{
			Host: host, Port: int32(port), SourceKind: securityv1alpha1.SourceKindGateway,
			SourceNamespace: obj.GetNamespace(), SourceName: obj.GetName(),
		})
	}
	return endpoints
}

// GenerateCRName creates a deterministic CR name from an endpoint.
// Format: <sanitized-host>-<port>-<8-char-hash>
// The hash is derived from sourceKind/sourceNamespace/sourceName/host/port.
func GenerateCRName(ep *Endpoint) string {
	// Generate hash from the full identity
	identity := fmt.Sprintf("%s/%s/%s/%s/%d", ep.SourceKind, ep.SourceNamespace, ep.SourceName, ep.Host, ep.Port)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))[:8]

	// Sanitize host for use in K8s name (dots and colons become hyphens)
	sanitized := strings.ToLower(ep.Host)
	sanitized = strings.ReplaceAll(sanitized, ".", "-")
	sanitized = strings.ReplaceAll(sanitized, ":", "-")
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

// probePortInfo tracks whether a port is used by a health probe and its scheme.
type probePortInfo struct {
	isHTTPS bool
}

// collectProbePorts builds a map of port numbers used by health probes
// (liveness, readiness, startup) across all containers in a pod.
// Named ports in probes are resolved against the container's port declarations.
func collectProbePorts(pod *corev1.Pod) map[int32]probePortInfo {
	probePorts := make(map[int32]probePortInfo)

	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		portNames := buildPortNameMap(container)
		probes := []*corev1.Probe{
			container.LivenessProbe,
			container.ReadinessProbe,
			container.StartupProbe,
		}

		for _, probe := range probes {
			if probe == nil {
				continue
			}

			if probe.HTTPGet != nil {
				port := resolveProbePort(probe.HTTPGet.Port, portNames)
				if port > 0 {
					info := probePorts[port]
					if probe.HTTPGet.Scheme == corev1.URISchemeHTTPS {
						info.isHTTPS = true
					}
					probePorts[port] = info
				}
			}

			if probe.TCPSocket != nil {
				port := resolveProbePort(probe.TCPSocket.Port, portNames)
				if port > 0 {
					if _, exists := probePorts[port]; !exists {
						probePorts[port] = probePortInfo{}
					}
				}
			}

			if probe.GRPC != nil && probe.GRPC.Port > 0 {
				if _, exists := probePorts[probe.GRPC.Port]; !exists {
					probePorts[probe.GRPC.Port] = probePortInfo{}
				}
			}
		}
	}

	return probePorts
}

// buildPortNameMap creates a name-to-number mapping from a container's declared ports.
func buildPortNameMap(container *corev1.Container) map[string]int32 {
	m := make(map[string]int32)
	for _, p := range container.Ports {
		if p.Name != "" {
			m[p.Name] = p.ContainerPort
		}
	}
	return m
}

// resolveProbePort converts an intstr.IntOrString port to a port number,
// resolving named ports against the container's port declarations.
func resolveProbePort(port intstr.IntOrString, portNames map[string]int32) int32 {
	if port.Type == intstr.Int {
		return port.IntVal
	}
	if resolved, ok := portNames[port.StrVal]; ok {
		return resolved
	}
	return 0
}

// podIPs returns all IP addresses for a pod, supporting dual-stack clusters.
// Falls back to the singular PodIP field for older clusters.
func podIPs(pod *corev1.Pod) []string {
	if len(pod.Status.PodIPs) > 0 {
		ips := make([]string, 0, len(pod.Status.PodIPs))
		for _, pip := range pod.Status.PodIPs {
			if pip.IP != "" {
				ips = append(ips, pip.IP)
			}
		}
		if len(ips) > 0 {
			return ips
		}
	}
	if pod.Status.PodIP != "" {
		return []string{pod.Status.PodIP}
	}
	return nil
}

// ExtractFromPod returns TLS endpoints from a Pod.
// It inspects container ports for known TLS ports or ports named https/https-*.
// On dual-stack clusters, endpoints are created for each pod IP (IPv4 and IPv6).
// Ports used only by HTTP/TCP health probes are skipped (plaintext expected).
// HTTPS health probe ports are still included but marked as probe ports.
// Only Running pods with a PodIP are considered. Init containers are skipped.
func ExtractFromPod(pod *corev1.Pod) []Endpoint {
	if pod.Status.Phase != corev1.PodRunning {
		return nil
	}

	ips := podIPs(pod)
	if len(ips) == 0 {
		return nil
	}

	probePorts := collectProbePorts(pod)

	var endpoints []Endpoint
	seen := make(map[int32]bool)

	for ci := range pod.Spec.Containers {
		for _, port := range pod.Spec.Containers[ci].Ports {
			if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP {
				continue
			}
			if seen[port.ContainerPort] {
				continue
			}
			if isTLSContainerPort(port) {
				seen[port.ContainerPort] = true

				probeInfo, isProbe := probePorts[port.ContainerPort]
				if isProbe && !probeInfo.isHTTPS {
					continue
				}

				for _, ip := range ips {
					endpoints = append(endpoints, Endpoint{
						Host:            ip,
						Port:            port.ContainerPort,
						SourceKind:      securityv1alpha1.SourceKindPod,
						SourceNamespace: pod.Namespace,
						SourceName:      pod.Name,
						IsProbePort:     isProbe,
					})
				}
			}
		}
	}

	return endpoints
}

var defaultTLSPorts = map[int32]bool{
	443: true, 2379: true, 2380: true,
	5443: true, 5671: true,
	6380: true, 6443: true,
	7443: true, 8443: true,
	9091: true, 9092: true, 9093: true,
	9100: true, 9200: true, 9443: true,
	10250: true, 10257: true, 10259: true,
}

var (
	extraTLSPorts   = map[int32]bool{}
	extraTLSPortsMu sync.RWMutex
)

// SetExtraTLSPorts configures additional port numbers to treat as TLS endpoints.
func SetExtraTLSPorts(ports map[int32]bool) {
	extraTLSPortsMu.Lock()
	defer extraTLSPortsMu.Unlock()
	extraTLSPorts = ports
}

// isTLSPortByNumberAndName checks if a port number and name indicate a TLS port.
// Shared logic for both ServicePort and ContainerPort classification.
func isTLSPortByNumberAndName(portNumber int32, portName string) bool {
	extraTLSPortsMu.RLock()
	extra := extraTLSPorts[portNumber]
	extraTLSPortsMu.RUnlock()
	if defaultTLSPorts[portNumber] || extra {
		return true
	}

	name := strings.ToLower(portName)
	return name == "https" || strings.HasPrefix(name, "https-")
}

// isTLSContainerPort checks if a ContainerPort is likely a TLS port.
func isTLSContainerPort(port corev1.ContainerPort) bool {
	return isTLSPortByNumberAndName(port.ContainerPort, port.Name)
}

// isTLSPort checks if a ServicePort is likely a TLS port
func isTLSPort(port *corev1.ServicePort) bool {
	return isTLSPortByNumberAndName(port.Port, port.Name)
}
