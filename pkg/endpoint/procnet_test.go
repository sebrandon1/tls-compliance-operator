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
	"net"
	"reflect"
	"testing"
)

func TestParseProcNetListeners(t *testing.T) {
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:24E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12347 1 0000000000000000 100 0 0 10 0
   3: 0100007F:01BB 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12348 1 0000000000000000 100 0 0 10 0
   4: not-a-valid-row
`
	got := ParseProcNetListeners(content)
	want := []ProcNetListener{
		{Port: 80, Address: net.ParseIP("::1")},
		{Port: 443, Address: net.ParseIP("0.0.0.0")},
		{Port: 9443, Address: net.ParseIP("127.0.0.1")},
	}
	if len(got) != len(want) {
		t.Fatalf("ParseProcNetListeners() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Port != want[i].Port || !got[i].Address.Equal(want[i].Address) {
			t.Errorf("listener[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseProcNetListeners_Deduplicates(t *testing.T) {
	content := `  sl  local_address rem_address   st
   0: 0100007F:01BB 00000000:0000 0A 0 0 1 1 0 0 100 0 0 10 0
   1: 0100007F:01BB 00000000:0000 0A 0 0 2 1 0 0 100 0 0 10 0
   2: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 0 0 3 1 0 0 100 0 0 10 0
`
	got := ParseProcNetListeners(content)
	if len(got) != 2 {
		t.Fatalf("ParseProcNetListeners() = %v, want 2 entries", got)
	}
	if !IsLoopbackOnly(listenAddressStrings(got)) {
		t.Errorf("addresses %v should be loopback-only", listenAddressStrings(got))
	}
}

func TestDecodeProcNetAddr(t *testing.T) {
	tests := []struct {
		name    string
		hexAddr string
		want    string
		wantOK  bool
	}{
		{name: "ipv4 loopback", hexAddr: "0100007F", want: "127.0.0.1", wantOK: true},
		{name: "ipv4 wildcard", hexAddr: "00000000", want: "0.0.0.0", wantOK: true},
		{name: "ipv4 specific", hexAddr: "0501F40A", want: "10.244.1.5", wantOK: true},
		{name: "ipv6 loopback", hexAddr: "00000000000000000000000001000000", want: "::1", wantOK: true},
		{name: "ipv6 wildcard", hexAddr: "00000000000000000000000000000000", want: "::", wantOK: true},
		{name: "ipv6 link local", hexAddr: "000080FE000000000000000000000000", want: "fe80::", wantOK: true},
		{name: "ipv4 mapped", hexAddr: "0000000000000000FFFF00000100007F", want: "127.0.0.1", wantOK: true},
		{name: "short", hexAddr: "0100", wantOK: false},
		{name: "not hex", hexAddr: "zzzzzzzz", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := decodeProcNetAddr(tt.hexAddr)
			if ok != tt.wantOK {
				t.Fatalf("decodeProcNetAddr(%q) ok = %v, want %v", tt.hexAddr, ok, tt.wantOK)
			}
			if ok && got.String() != tt.want {
				t.Errorf("decodeProcNetAddr(%q) = %s, want %s", tt.hexAddr, got, tt.want)
			}
		})
	}
}

func TestIsLoopbackOnly(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  bool
	}{
		{name: "empty is unknown", addrs: nil, want: false},
		{name: "ipv4 loopback", addrs: []string{"127.0.0.1"}, want: true},
		{name: "ipv6 loopback", addrs: []string{"::1"}, want: true},
		{name: "both loopback", addrs: []string{"127.0.0.1", "::1"}, want: true},
		{name: "wildcard", addrs: []string{"0.0.0.0"}, want: false},
		{name: "ipv6 wildcard", addrs: []string{"::"}, want: false},
		{name: "specific address", addrs: []string{"10.244.1.5"}, want: false},
		{name: "mixed", addrs: []string{"127.0.0.1", "0.0.0.0"}, want: false},
		{name: "invalid", addrs: []string{"not-an-ip"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLoopbackOnly(tt.addrs); got != tt.want {
				t.Errorf("IsLoopbackOnly(%v) = %v, want %v", tt.addrs, got, tt.want)
			}
		})
	}
}

// listenAddressStrings returns the addresses of listeners for test assertions.
func listenAddressStrings(listeners []ProcNetListener) []string {
	out := make([]string, 0, len(listeners))
	for _, listener := range listeners {
		out = append(out, listener.Address.String())
	}
	return out
}

func TestParseProcNetListeners_RejectsMalformedLocalAddress(t *testing.T) {
	content := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:0000 00000000:0000 0A 0 0 1 1 0 0 100 0 0 10 0\n" + // port 0
		"   1: 0100:01BB 00000000:0000 0A 0 0 1 1 0 0 100 0 0 10 0\n" + // bad address length
		"   2: 0100007F:01BB 00000000:0000 0A 0 0 1 1 0 0 100 0 0 10 0\n"
	got := ParseProcNetListeners(content)
	if len(got) != 1 || got[0].Port != 443 {
		t.Fatalf("ParseProcNetListeners() = %v, want only the valid 443 row", got)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	// Ports: 443 = 0x01BB, 9443 = 0x24E3, 22 = 0x0016.
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:24E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
   3: 00000000:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12348 1 0000000000000000 100 0 0 10 0
   4: not-a-valid-row
`
	got := ParseProcNetTCP(content)
	want := []int32{22, 443, 9443}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseProcNetTCP() = %v, want %v", got, want)
	}
}

func TestParseProcNetTCP_DeduplicatesAcrossV4AndV6(t *testing.T) {
	content := `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 0 100 0 0 10 0
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2 1 0 0 100 0 0 10 0
`
	got := ParseProcNetTCP(content)
	if !reflect.DeepEqual(got, []int32{443}) {
		t.Errorf("ParseProcNetTCP() = %v, want [443]", got)
	}
}

func TestParseProcNetTCP_Empty(t *testing.T) {
	if got := ParseProcNetTCP(""); len(got) != 0 {
		t.Errorf("ParseProcNetTCP(\"\") = %v, want empty", got)
	}
	if got := ParseProcNetTCP("  sl  local_address rem_address   st\n"); len(got) != 0 {
		t.Errorf("ParseProcNetTCP(header) = %v, want empty", got)
	}
}

func TestProcNetLocalPort_RejectsZeroAndGarbage(t *testing.T) {
	for _, in := range []string{"00000000:0000", "00000000", "zzzz"} {
		if _, ok := procNetLocalPort(in); ok {
			t.Errorf("procNetLocalPort(%q) ok = true, want false", in)
		}
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    PortRange
		wantErr bool
	}{
		{name: "valid", value: "2000-30000", want: PortRange{Start: 2000, End: 30000}},
		{name: "single port", value: "443-443", want: PortRange{Start: 443, End: 443}},
		{name: "reversed", value: "30000-2000", wantErr: true},
		{name: "no separator", value: "2000", wantErr: true},
		{name: "zero", value: "0-100", wantErr: true},
		{name: "too high", value: "1-70000", wantErr: true},
		{name: "not a number", value: "a-b", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortRange(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePortRange(%q) error = nil, want an error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortRange(%q) error = %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("ParsePortRange(%q) = %+v, want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestPortRange_Filter(t *testing.T) {
	r := PortRange{Start: 8000, End: 9000}
	got := r.Filter([]int32{22, 8443, 9000, 9443})
	if !reflect.DeepEqual(got, []int32{8443, 9000}) {
		t.Errorf("Filter() = %v, want [8443 9000]", got)
	}
}
