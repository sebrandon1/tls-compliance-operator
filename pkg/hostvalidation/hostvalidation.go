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

package hostvalidation

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// ErrReservedAddress is returned by DialControl when a connection would reach
// a reserved or internal address.
var ErrReservedAddress = errors.New("dial to reserved address blocked")

var reservedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // IPv4 link-local (includes cloud metadata 169.254.169.254)
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"fc00::/7",       // IPv6 unique local
		"0.0.0.0/8",      // unspecified
		"100.64.0.0/10",  // RFC 6598 CGNAT (includes Alibaba metadata 100.100.100.200)
		"192.0.0.0/24",   // IETF protocol assignments (includes OCI metadata 192.0.0.192)
		"198.18.0.0/15",  // RFC 2544 benchmarking
		"224.0.0.0/4",    // IPv4 multicast
		"240.0.0.0/4",    // reserved (includes broadcast 255.255.255.255)
		"ff00::/8",       // IPv6 multicast
		"64:ff9b::/96",   // NAT64 (can embed any IPv4, including 169.254.169.254)
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return nets
}()

var internalHostSuffixes = []string{
	".localhost",
}

var internalHostExact = []string{
	"localhost",
	"metadata.google.internal",
	"metadata",
	"instance-data",
}

// IsReservedIP returns true if the IP falls within a reserved or private CIDR.
func IsReservedIP(ip net.IP) bool {
	for _, cidr := range reservedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsInternalHostname returns true if the hostname matches a known
// internal or infrastructure-internal name.
func IsInternalHostname(host string) bool {
	lower := strings.ToLower(host)
	for _, exact := range internalHostExact {
		if lower == exact {
			return true
		}
	}
	for _, suffix := range internalHostSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// IsSafeHost returns true if the host (IP or hostname) is safe to probe.
func IsSafeHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return !IsReservedIP(ip)
	}
	return !IsInternalHostname(host)
}

// DialControl is a net.Dialer Control hook that refuses connections to
// reserved addresses. It runs after DNS resolution, so it also catches
// hostnames that resolve (or rebind) to internal IPs.
func DialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || IsReservedIP(ip) {
		return fmt.Errorf("%w: %s", ErrReservedAddress, host)
	}
	return nil
}
