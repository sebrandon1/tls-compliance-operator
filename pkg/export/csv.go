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
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// CSVHeader is the header row for CSV exports.
var CSVHeader = []string{
	"Host", "Port", "Source", "Namespace", "Name",
	"Compliance", "Grade", "ForwardSecrecy", "KeyExchange",
	"TLS1.3", "TLS1.2", "TLS1.1", "TLS1.0",
	"QuantumReady", "PQCReadiness",
	"CertExpiry", "CertIssuer",
}

// WriteCSV writes TLSComplianceReport items as CSV to the given writer.
func WriteCSV(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write(CSVHeader); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for i := range reports {
		row := reportToCSVRow(&reports[i])
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return cw.Error()
}

// extractCertInfo returns the formatted expiry date and issuer from a report's certificate info.
func extractCertInfo(r *securityv1alpha1.TLSComplianceReport) (certExpiry, certIssuer string) {
	if r.Status.CertificateInfo != nil {
		if r.Status.CertificateInfo.NotAfter != nil {
			certExpiry = r.Status.CertificateInfo.NotAfter.Format("2006-01-02")
		}
		certIssuer = r.Status.CertificateInfo.Issuer
	}
	return
}

// formatKeyExchangeTypes returns a compact string of unique key exchange types
// across all TLS versions, sorted alphabetically (e.g. "ECDHE,TLS13").
func formatKeyExchangeTypes(keTypes map[string]string) string {
	if len(keTypes) == 0 {
		return ""
	}
	seen := make(map[string]bool)
	for _, ke := range keTypes {
		for _, part := range strings.Split(ke, ",") {
			seen[part] = true
		}
	}
	unique := make([]string, 0, len(seen))
	for ke := range seen {
		unique = append(unique, ke)
	}
	sort.Strings(unique)
	return strings.Join(unique, ",")
}

func reportToCSVRow(r *securityv1alpha1.TLSComplianceReport) []string {
	certExpiry, certIssuer := extractCertInfo(r)

	return []string{
		r.Spec.Host,
		strconv.Itoa(int(r.Spec.Port)),
		string(r.Spec.SourceKind),
		r.Spec.SourceNamespace,
		r.Spec.SourceName,
		string(r.Status.ComplianceStatus),
		r.Status.OverallCipherGrade,
		strconv.FormatBool(r.Status.ForwardSecrecy),
		formatKeyExchangeTypes(r.Status.KeyExchangeTypes),
		strconv.FormatBool(r.Status.TLSVersions.TLS13),
		strconv.FormatBool(r.Status.TLSVersions.TLS12),
		strconv.FormatBool(r.Status.TLSVersions.TLS11),
		strconv.FormatBool(r.Status.TLSVersions.TLS10),
		strconv.FormatBool(r.Status.QuantumReady),
		string(r.Status.PQCReadiness),
		certExpiry,
		certIssuer,
	}
}
