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

package export

import (
	"bytes"
	"encoding/xml"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// failingWriter fails every write, exercising writer error paths.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func makeNamedReport(kind, name string, port int32) securityv1alpha1.TLSComplianceReport {
	return securityv1alpha1.TLSComplianceReport{
		Spec: securityv1alpha1.TLSComplianceReportSpec{
			Host:            "10.1.2.3",
			Port:            port,
			SourceKind:      securityv1alpha1.SourceKind(kind),
			SourceNamespace: "prod",
			SourceName:      name,
		},
		Status: securityv1alpha1.TLSComplianceReportStatus{
			ComplianceStatus: securityv1alpha1.ComplianceStatusCompliant,
		},
	}
}

func TestCaseName_Service(t *testing.T) {
	got := CaseName(ptrReport(makeNamedReport("Service", "web", 443)))
	if want := "ns/prod Service/web port/443"; got != want {
		t.Errorf("CaseName() = %q, want %q", got, want)
	}
}

func TestCaseName_ClusterScopedOmitsNamespace(t *testing.T) {
	r := makeNamedReport("Node", "worker-0", 10250)
	r.Spec.SourceNamespace = ""

	if got, want := CaseName(&r), "Node/worker-0 port/10250"; got != want {
		t.Errorf("CaseName() = %q, want %q", got, want)
	}
}

func TestCaseName_PodUsesWorkload(t *testing.T) {
	r := makeNamedReport("Pod", "web-6b7f9c4d5-abcde", 8443)
	r.Status.WorkloadKind = "ReplicaSet"
	r.Status.WorkloadName = "web-6b7f9c4d5"

	got := CaseName(&r)
	if want := "ns/prod ReplicaSet/web-6b7f9c4d5 port/8443"; got != want {
		t.Errorf("CaseName() = %q, want %q", got, want)
	}
}

func TestCaseName_StableAcrossPodRecreation(t *testing.T) {
	first := makeNamedReport("Pod", "web-6b7f9c4d5-abcde", 8443)
	first.Status.WorkloadKind = "DaemonSet"
	first.Status.WorkloadName = "node-agent"

	second := makeNamedReport("Pod", "web-6b7f9c4d5-zzzzz", 8443)
	second.Status.WorkloadKind = "DaemonSet"
	second.Status.WorkloadName = "node-agent"

	first.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusCompliant
	second.Status.ComplianceStatus = securityv1alpha1.ComplianceStatusNonCompliant
	if CaseName(&first) != CaseName(&second) {
		t.Errorf("names differ across pod recreation: %q vs %q", CaseName(&first), CaseName(&second))
	}
}

func TestWriteJUnit_AdherenceTag(t *testing.T) {
	withProfile := makeNamedReport("Service", "api", 443)
	withProfile.Status.APIServerProfileCompliance = &securityv1alpha1.TLSProfileComplianceResult{ProfileType: "Intermediate"}
	withoutProfile := makeNamedReport("Service", "web", 443)

	var buf bytes.Buffer
	if err := WriteJUnit(&buf, []securityv1alpha1.TLSComplianceReport{withProfile, withoutProfile}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	cases := suites.TestSuites[0].TestCases
	if cases[0].Name != "ns/prod Service/api port/443 [OCPFeatureGate:TLSAdherence]" {
		t.Errorf("adherence case name = %q", cases[0].Name)
	}
	if cases[1].Name != "ns/prod Service/web port/443" {
		t.Errorf("non-adherence case name = %q", cases[1].Name)
	}
}

func TestWriteJUnit_UniqueNamesAndProperties(t *testing.T) {
	reports := []securityv1alpha1.TLSComplianceReport{
		makeNamedReport("Service", "web", 443),
		makeNamedReport("Service", "web", 443),
	}
	reports[0].Status.OverallCipherGrade = "A"
	reports[0].Status.PQCReadiness = securityv1alpha1.PQCReadinessPQCReady
	expiry := metav1.NewTime(time.Date(2027, time.March, 1, 12, 30, 0, 0, time.UTC))
	reports[0].Status.CertificateInfo = &securityv1alpha1.CertificateInfo{NotAfter: &expiry}

	var buf bytes.Buffer
	if err := WriteJUnit(&buf, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	cases := suites.TestSuites[0].TestCases
	if cases[0].Name != "ns/prod Service/web port/443" {
		t.Errorf("first case name = %q", cases[0].Name)
	}
	if cases[1].Name != "ns/prod Service/web port/443 #2" {
		t.Errorf("second case name = %q, want a #2 suffix", cases[1].Name)
	}

	props := map[string]string{}
	for _, p := range cases[0].Properties {
		props[p.Name] = p.Value
	}
	for name, want := range map[string]string{
		"endpoint":         "10.1.2.3:443",
		"complianceStatus": "Compliant",
		"cipherGrade":      "A",
		"pqcReadiness":     "PQCReady",
		"certNotAfter":     "2027-03-01T12:30:00Z",
	} {
		if props[name] != want {
			t.Errorf("property %q = %q, want %q", name, props[name], want)
		}
	}

	if cases[0].ClassName != "Service" {
		t.Errorf("ClassName = %q, want Service", cases[0].ClassName)
	}
}

func TestWriteJUnit_WriterError(t *testing.T) {
	err := WriteJUnit(failingWriter{}, []securityv1alpha1.TLSComplianceReport{
		makeNamedReport("Service", "web", 443),
	})
	if err == nil {
		t.Fatal("expected an error from a failing writer")
	}
}

func ptrReport(r securityv1alpha1.TLSComplianceReport) *securityv1alpha1.TLSComplianceReport {
	return &r
}
