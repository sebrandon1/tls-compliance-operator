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
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func TestParseImportData_YAMLList(t *testing.T) {
	data := []byte(`apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceTargetList
items:
  - metadata:
      name: a
    spec:
      host: example.com
      port: 8443
  - metadata:
      name: b
    spec:
      host: example.net
`)
	targets, err := parseImportData(data)
	if err != nil {
		t.Fatalf("parseImportData() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Host != "example.com" || targets[0].Port != 8443 {
		t.Errorf("targets[0] = %+v", targets[0])
	}
	if targets[1].Host != "example.net" || targets[1].Port != 443 {
		t.Errorf("targets[1] = %+v, want the default port", targets[1])
	}
}

func TestParseImportData_SingleTarget(t *testing.T) {
	data := []byte(`apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceTarget
metadata:
  name: only
spec:
  host: single.example
  port: 9443
`)
	targets, err := parseImportData(data)
	if err != nil {
		t.Fatalf("parseImportData() error = %v", err)
	}
	if len(targets) != 1 || targets[0].Host != "single.example" || targets[0].Port != 9443 {
		t.Fatalf("targets = %+v", targets)
	}
}

func TestParseImportData_HostPortLines(t *testing.T) {
	data := []byte("# partner endpoints\nexample.com\nexample.net:8443\n")
	targets, err := parseImportData(data)
	if err != nil {
		t.Fatalf("parseImportData() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %+v, want 2", targets)
	}
	if targets[0].Port != 443 || targets[1].Port != 8443 {
		t.Errorf("ports = %d/%d, want 443/8443", targets[0].Port, targets[1].Port)
	}
}

func TestParseImportData_InvalidPort(t *testing.T) {
	if _, err := parseImportData([]byte("example.com:70000\n")); err == nil {
		t.Fatal("parseImportData() error = nil, want an error for an out-of-range port")
	}
}

func TestTargetName(t *testing.T) {
	if got := targetName("API.Example.com", 443); got != "api-example-com-443" {
		t.Errorf("targetName() = %q", got)
	}
}

func TestRunTargetImport_CreatesThenSkips(t *testing.T) {
	useFakeCommandClient(t)

	path := t.TempDir() + "/endpoints.txt"
	if err := os.WriteFile(path, []byte("example.com\nexample.net:8443\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	var out bytes.Buffer
	if err := runTargetImport(&cobra.Command{}, path, &out); err != nil {
		t.Fatalf("runTargetImport() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "created 2 target(s), skipped 0") {
		t.Errorf("output = %q, want 2 created", got)
	}

	out.Reset()
	if err := runTargetImport(&cobra.Command{}, path, &out); err != nil {
		t.Fatalf("second runTargetImport() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "created 0 target(s), skipped 2") {
		t.Errorf("output = %q, want 2 skipped on re-import", got)
	}
}

func TestRunTargetExport_RoundTripsThroughImport(t *testing.T) {
	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "example-com-443"},
		Spec:       securityv1alpha1.TLSComplianceTargetSpec{Host: "example.com", Port: int32Pointer(443)},
	}
	useFakeCommandClient(t, target)

	var out bytes.Buffer
	if err := runTargetExport(&cobra.Command{}, "", &out); err != nil {
		t.Fatalf("runTargetExport() error = %v", err)
	}
	if !strings.Contains(out.String(), "kind: TLSComplianceTargetList") || !strings.Contains(out.String(), "host: example.com") {
		t.Fatalf("export output = %q, want a target list with the host", out.String())
	}

	// The export must be accepted by the importer.
	targets, err := parseImportData(out.Bytes())
	if err != nil {
		t.Fatalf("parseImportData(export) error = %v", err)
	}
	if len(targets) != 1 || targets[0].Host != "example.com" || targets[0].Port != 443 {
		t.Errorf("round-trip targets = %+v", targets)
	}
}

func TestRunTargetExport_ToFile(t *testing.T) {
	useFakeCommandClient(t)
	path := t.TempDir() + "/targets.yaml"

	var out bytes.Buffer
	if err := runTargetExport(&cobra.Command{}, path, &out); err != nil {
		t.Fatalf("runTargetExport() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("export file missing: %v", err)
	}
}

func TestSplitHostPort_IPv6Bracketed(t *testing.T) {
	if host, port := splitHostPort("[2001:db8::1]:8443"); host != "2001:db8::1" || port != 8443 {
		t.Errorf("splitHostPort() = %q, %d; want 2001:db8::1, 8443", host, port)
	}
	if host, port := splitHostPort("[2001:db8::1]"); host != "2001:db8::1" || port != 443 {
		t.Errorf("splitHostPort() = %q, %d; want the default port", host, port)
	}
	if host, _ := splitHostPort("[broken"); host != "" {
		t.Errorf("splitHostPort() = %q, want rejection of unterminated bracket", host)
	}
}
