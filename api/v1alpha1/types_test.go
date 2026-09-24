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

package v1alpha1

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAPIGroupTypesRegisterWithScheme(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	for _, object := range []runtime.Object{
		&TLSComplianceTarget{},
		&TLSComplianceTargetList{},
		&TLSComplianceReport{},
		&TLSComplianceReportList{},
	} {
		gvks, _, err := scheme.ObjectKinds(object)
		if err != nil {
			t.Errorf("ObjectKinds(%T) error = %v", object, err)
			continue
		}
		if len(gvks) != 1 || gvks[0].GroupVersion() != GroupVersion {
			t.Errorf("ObjectKinds(%T) = %v, want one %s GVK", object, gvks, GroupVersion)
		}
	}
}

func TestTLSComplianceTargetPortJSONPresence(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantPresent bool
		wantPort    int32
	}{
		{name: "omitted", json: `{"spec":{"host":"example.com"}}`},
		{name: "explicit zero", json: `{"spec":{"host":"example.com","port":0}}`, wantPresent: true},
		{name: "custom port", json: `{"spec":{"host":"example.com","port":8443}}`, wantPresent: true, wantPort: 8443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target TLSComplianceTarget
			if err := json.Unmarshal([]byte(tt.json), &target); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if (target.Spec.Port != nil) != tt.wantPresent {
				t.Fatalf("port presence = %t, want %t", target.Spec.Port != nil, tt.wantPresent)
			}
			if target.Spec.Port != nil && *target.Spec.Port != tt.wantPort {
				t.Errorf("port = %d, want %d", *target.Spec.Port, tt.wantPort)
			}
		})
	}
}

func TestTLSComplianceTargetDeepCopyCopiesPort(t *testing.T) {
	port := int32(443)
	original := &TLSComplianceTarget{Spec: TLSComplianceTargetSpec{Port: &port}}
	copy := original.DeepCopy()
	*copy.Spec.Port = 8443

	if *original.Spec.Port != 443 {
		t.Errorf("original port = %d, want 443 after changing deep copy", *original.Spec.Port)
	}
}

func TestCRDEnumValues(t *testing.T) {
	sourceKinds := []struct {
		name string
		got  SourceKind
		want string
	}{
		{"Service", SourceKindService, "Service"},
		{"Ingress", SourceKindIngress, "Ingress"},
		{"Route", SourceKindRoute, "Route"},
		{"Target", SourceKindTarget, "Target"},
		{"Pod", SourceKindPod, "Pod"},
		{"HTTPRoute", SourceKindHTTPRoute, "HTTPRoute"},
		{"TLSRoute", SourceKindTLSRoute, "TLSRoute"},
		{"GRPCRoute", SourceKindGRPCRoute, "GRPCRoute"},
		{"Gateway", SourceKindGateway, "Gateway"},
	}
	for _, tt := range sourceKinds {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Errorf("value = %q, want %q", tt.got, tt.want)
			}
		})
	}

	complianceStatuses := []struct {
		name string
		got  ComplianceStatus
		want string
	}{
		{"Compliant", ComplianceStatusCompliant, "Compliant"},
		{"NonCompliant", ComplianceStatusNonCompliant, "NonCompliant"},
		{"Warning", ComplianceStatusWarning, "Warning"},
		{"Unreachable", ComplianceStatusUnreachable, "Unreachable"},
		{"Timeout", ComplianceStatusTimeout, "Timeout"},
		{"Closed", ComplianceStatusClosed, "Closed"},
		{"Filtered", ComplianceStatusFiltered, "Filtered"},
		{"NoTLS", ComplianceStatusNoTLS, "NoTLS"},
		{"PlaintextHTTP", ComplianceStatusPlaintextHTTP, "PlaintextHTTP"},
		{"MutualTLSRequired", ComplianceStatusMutualTLSRequired, "MutualTLSRequired"},
		{"Pending", ComplianceStatusPending, "Pending"},
		{"Unknown", ComplianceStatusUnknown, "Unknown"},
	}
	for _, tt := range complianceStatuses {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Errorf("value = %q, want %q", tt.got, tt.want)
			}
		})
	}

	pqcReadiness := []struct {
		name string
		got  PQCReadiness
		want string
	}{
		{"PQCReady", PQCReadinessPQCReady, "PQCReady"},
		{"TLS13Capable", PQCReadinessTLS13Capable, "TLS13Capable"},
		{"LegacyTLS", PQCReadinessLegacyTLS, "LegacyTLS"},
		{"NoPQC", PQCReadinessNoPQC, "NoPQC"},
	}
	for _, tt := range pqcReadiness {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Errorf("value = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestTLSComplianceReportJSONRoundTripPreservesOptionalFields(t *testing.T) {
	hostnameMatch := false
	serverPrefersOwnCiphers := true
	checkedAt := metav1.NewTime(time.Unix(1_700_000_000, 0).UTC())
	report := &TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: "report"},
		Spec: TLSComplianceReportSpec{
			Host: "example.com", Port: 443, SourceKind: SourceKindService,
			SourceNamespace: "default", SourceName: "example",
		},
		Status: TLSComplianceReportStatus{
			ComplianceStatus:        ComplianceStatusCompliant,
			TLSVersions:             TLSVersionSupport{TLS12: true, TLS13: true},
			CipherSuites:            map[string][]string{"TLSv1.3": {"TLS_AES_128_GCM_SHA256"}},
			ServerPrefersOwnCiphers: &serverPrefersOwnCiphers,
			CertificateInfo:         &CertificateInfo{HostnameMatch: &hostnameMatch, NotAfter: &checkedAt},
			History:                 []ComplianceHistoryEntry{{ComplianceStatus: ComplianceStatusWarning, Timestamp: &checkedAt}},
			ImageCertificationInfo:  []ContainerImageCertInfo{{ContainerName: "app", ImageRef: "registry.example/app@sha256:abc"}},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var got TLSComplianceReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got.Spec != report.Spec || got.Status.ComplianceStatus != report.Status.ComplianceStatus ||
		!reflect.DeepEqual(got.Status.TLSVersions, report.Status.TLSVersions) ||
		!reflect.DeepEqual(got.Status.CipherSuites, report.Status.CipherSuites) ||
		*got.Status.ServerPrefersOwnCiphers != *report.Status.ServerPrefersOwnCiphers ||
		*got.Status.CertificateInfo.HostnameMatch != *report.Status.CertificateInfo.HostnameMatch ||
		!got.Status.CertificateInfo.NotAfter.Time.Equal(report.Status.CertificateInfo.NotAfter.Time) ||
		!got.Status.History[0].Timestamp.Time.Equal(report.Status.History[0].Timestamp.Time) ||
		!reflect.DeepEqual(got.Status.ImageCertificationInfo, report.Status.ImageCertificationInfo) {
		t.Fatalf("JSON round trip changed report:\n got  %#v\n want %#v", got, *report)
	}
}

func TestTLSComplianceReportDeepCopyIsIndependent(t *testing.T) {
	hostnameMatch := true
	original := &TLSComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"environment": "test"}},
		Status: TLSComplianceReportStatus{
			CertificateInfo: &CertificateInfo{HostnameMatch: &hostnameMatch, DNSNames: []string{"example.com"}},
			CipherSuites:    map[string][]string{"TLSv1.3": {"TLS_AES_128_GCM_SHA256"}},
			History:         []ComplianceHistoryEntry{{ComplianceStatus: ComplianceStatusCompliant}},
		},
	}

	copy := original.DeepCopy()
	copy.Labels["environment"] = "production"
	*copy.Status.CertificateInfo.HostnameMatch = false
	copy.Status.CertificateInfo.DNSNames[0] = "changed.example.com"
	copy.Status.CipherSuites["TLSv1.3"][0] = "changed"
	copy.Status.History[0].ComplianceStatus = ComplianceStatusWarning

	if original.Labels["environment"] != "test" ||
		*original.Status.CertificateInfo.HostnameMatch != true ||
		original.Status.CertificateInfo.DNSNames[0] != "example.com" ||
		original.Status.CipherSuites["TLSv1.3"][0] != "TLS_AES_128_GCM_SHA256" ||
		original.Status.History[0].ComplianceStatus != ComplianceStatusCompliant {
		t.Error("DeepCopy() did not isolate nested metadata and status fields")
	}
}
