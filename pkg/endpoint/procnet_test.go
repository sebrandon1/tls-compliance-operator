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
	"reflect"
	"testing"
)

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
