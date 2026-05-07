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
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

var markdownHeader = []string{
	"Host", "Port", "Source", "Compliance", "Grade", "FS",
	"TLS1.3", "TLS1.2", "TLS1.0", "PQC", "CertExpiry", "Age",
}

// WriteMarkdown writes TLSComplianceReport items as a Markdown table to the given writer.
// Columns match kubectl get tlsreport output for familiarity.
func WriteMarkdown(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	if _, err := fmt.Fprintf(w, "| %s |\n", strings.Join(markdownHeader, " | ")); err != nil {
		return err
	}

	separators := make([]string, len(markdownHeader))
	for i := range separators {
		separators[i] = "---"
	}
	if _, err := fmt.Fprintf(w, "| %s |\n", strings.Join(separators, " | ")); err != nil {
		return err
	}

	now := time.Now()
	for i := range reports {
		row := reportToMarkdownRow(&reports[i], now)
		if _, err := fmt.Fprintf(w, "| %s |\n", strings.Join(row, " | ")); err != nil {
			return err
		}
	}

	return nil
}

func reportToMarkdownRow(r *securityv1alpha1.TLSComplianceReport, now time.Time) []string {
	var certExpiry, age string

	if r.Status.CertificateInfo != nil {
		certExpiry = strconv.Itoa(r.Status.CertificateInfo.DaysUntilExpiry)
	}

	if !r.CreationTimestamp.IsZero() {
		age = formatAge(now.Sub(r.CreationTimestamp.Time))
	}

	return []string{
		escPipe(r.Spec.Host),
		strconv.Itoa(int(r.Spec.Port)),
		string(r.Spec.SourceKind),
		string(r.Status.ComplianceStatus),
		r.Status.OverallCipherGrade,
		strconv.FormatBool(r.Status.ForwardSecrecy),
		strconv.FormatBool(r.Status.TLSVersions.TLS13),
		strconv.FormatBool(r.Status.TLSVersions.TLS12),
		strconv.FormatBool(r.Status.TLSVersions.TLS10),
		string(r.Status.PQCReadiness),
		certExpiry,
		age,
	}
}

func escPipe(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
