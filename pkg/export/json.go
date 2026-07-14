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
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// JSONReport is the structured representation of a single TLS compliance report,
// used by both JSON and YAML export (yaml.v3 falls back to json tags).
type JSONReport struct {
	Host               string            `json:"host"`
	Port               string            `json:"port"`
	Source             string            `json:"source"`
	Namespace          string            `json:"namespace"`
	Name               string            `json:"name"`
	Compliance         string            `json:"compliance"`
	Grade              string            `json:"grade"`
	ForwardSecrecy     bool              `json:"forwardSecrecy"`
	KeyExchangeTypes   map[string]string `json:"keyExchangeTypes,omitempty"`
	TLS13              bool              `json:"tls13"`
	TLS12              bool              `json:"tls12"`
	TLS11              bool              `json:"tls11"`
	TLS10              bool              `json:"tls10"`
	SSL30              bool              `json:"ssl30"`
	QuantumReady       bool              `json:"quantumReady"`
	PQCReadiness       string            `json:"pqcReadiness"`
	MLKEMSupported     bool              `json:"mlkemSupported"`
	CertExpiry         string            `json:"certExpiry"`
	CertIssuer         string            `json:"certIssuer"`
	PublicKeyAlgorithm string            `json:"publicKeyAlgorithm,omitempty"`
	PublicKeyBits      int               `json:"publicKeyBits,omitempty"`
	SignatureAlgorithm string            `json:"signatureAlgorithm,omitempty"`
	ChainLength        int               `json:"chainLength,omitempty"`
}

func buildExportSlice(reports []securityv1alpha1.TLSComplianceReport) []JSONReport {
	out := make([]JSONReport, 0, len(reports))
	for i := range reports {
		out = append(out, reportToJSON(&reports[i]))
	}
	return out
}

// WriteJSON writes TLSComplianceReport items as pretty-printed JSON to the given writer.
func WriteJSON(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(buildExportSlice(reports)); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	return nil
}

func reportToJSON(r *securityv1alpha1.TLSComplianceReport) JSONReport {
	certExpiry, certIssuer := extractCertInfo(r)

	jr := JSONReport{
		Host:             r.Spec.Host,
		Port:             strconv.Itoa(int(r.Spec.Port)),
		Source:           string(r.Spec.SourceKind),
		Namespace:        r.Spec.SourceNamespace,
		Name:             r.Spec.SourceName,
		Compliance:       string(r.Status.ComplianceStatus),
		Grade:            r.Status.OverallCipherGrade,
		ForwardSecrecy:   r.Status.ForwardSecrecy,
		KeyExchangeTypes: r.Status.KeyExchangeTypes,
		TLS13:            r.Status.TLSVersions.TLS13,
		TLS12:            r.Status.TLSVersions.TLS12,
		TLS11:            r.Status.TLSVersions.TLS11,
		TLS10:            r.Status.TLSVersions.TLS10,
		SSL30:            r.Status.TLSVersions.SSL30,
		QuantumReady:     r.Status.QuantumReady,
		PQCReadiness:     string(r.Status.PQCReadiness),
		MLKEMSupported:   r.Status.MLKEMSupported,
		CertExpiry:       certExpiry,
		CertIssuer:       certIssuer,
	}

	if r.Status.CertificateInfo != nil {
		jr.PublicKeyAlgorithm = r.Status.CertificateInfo.PublicKeyAlgorithm
		jr.PublicKeyBits = r.Status.CertificateInfo.PublicKeyBits
		jr.SignatureAlgorithm = r.Status.CertificateInfo.SignatureAlgorithm
		jr.ChainLength = r.Status.CertificateInfo.ChainLength
	}

	return jr
}
