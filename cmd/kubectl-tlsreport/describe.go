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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func newDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <name>",
		Short: "Show detailed information about a TLS compliance report",
		Example: `  # Describe a specific report
  kubectl tlsreport describe my-service-443-abc12345`,
		Args: cobra.ExactArgs(1),
		RunE: runDescribe,
	}
}

func runDescribe(cmd *cobra.Command, args []string) error {
	reports, err := fetchReports(cmd.Context())
	if err != nil {
		return err
	}

	name := args[0]
	for i := range reports {
		if reports[i].Name == name {
			return printReportDetail(&reports[i])
		}
	}
	return fmt.Errorf("report %q not found", name)
}

func printReportDetail(r *securityv1alpha1.TLSComplianceReport) error {
	w := os.Stdout

	_, _ = fmt.Fprintf(w, "Name:         %s\n", r.Name)
	_, _ = fmt.Fprintf(w, "Host:         %s\n", r.Spec.Host)
	_, _ = fmt.Fprintf(w, "Port:         %d\n", r.Spec.Port)
	_, _ = fmt.Fprintf(w, "Source Kind:  %s\n", r.Spec.SourceKind)
	_, _ = fmt.Fprintf(w, "Source:       %s/%s\n", r.Spec.SourceNamespace, r.Spec.SourceName)

	_, _ = fmt.Fprintf(w, "\nCompliance:\n")
	_, _ = fmt.Fprintf(w, "  Status:          %s\n", r.Status.ComplianceStatus)
	_, _ = fmt.Fprintf(w, "  PQC Readiness:   %s\n", r.Status.PQCReadiness)
	_, _ = fmt.Fprintf(w, "  Quantum Ready:   %v\n", r.Status.QuantumReady)
	_, _ = fmt.Fprintf(w, "  ML-KEM Supported: %v\n", r.Status.MLKEMSupported)
	if r.Status.FIPSDetected {
		_, _ = fmt.Fprintf(w, "  FIPS Mode:        Active -- ML-KEM unavailable\n")
	}
	_, _ = fmt.Fprintf(w, "  Cipher Grade:    %s\n", r.Status.OverallCipherGrade)
	_, _ = fmt.Fprintf(w, "  Forward Secrecy: %v\n", r.Status.ForwardSecrecy)

	_, _ = fmt.Fprintf(w, "\nTLS Versions:\n")
	_, _ = fmt.Fprintf(w, "  SSL 3.0:  %v\n", r.Status.TLSVersions.SSL30)
	_, _ = fmt.Fprintf(w, "  TLS 1.0:  %v\n", r.Status.TLSVersions.TLS10)
	_, _ = fmt.Fprintf(w, "  TLS 1.1:  %v\n", r.Status.TLSVersions.TLS11)
	_, _ = fmt.Fprintf(w, "  TLS 1.2:  %v\n", r.Status.TLSVersions.TLS12)
	_, _ = fmt.Fprintf(w, "  TLS 1.3:  %v\n", r.Status.TLSVersions.TLS13)

	if r.Status.CertificateInfo != nil {
		cert := r.Status.CertificateInfo
		_, _ = fmt.Fprintf(w, "\nCertificate:\n")
		_, _ = fmt.Fprintf(w, "  Issuer:           %s\n", cert.Issuer)
		_, _ = fmt.Fprintf(w, "  Subject:          %s\n", cert.Subject)
		if cert.NotBefore != nil {
			_, _ = fmt.Fprintf(w, "  Not Before:       %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
		}
		if cert.NotAfter != nil {
			_, _ = fmt.Fprintf(w, "  Not After:        %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
		}
		_, _ = fmt.Fprintf(w, "  Days Until Expiry: %d\n", cert.DaysUntilExpiry)
		_, _ = fmt.Fprintf(w, "  Is Expired:       %v\n", cert.IsExpired)
		if cert.HostnameMatch != nil {
			_, _ = fmt.Fprintf(w, "  Hostname Match:   %v\n", *cert.HostnameMatch)
		}
		if cert.PublicKeyAlgorithm != "" {
			_, _ = fmt.Fprintf(w, "  Public Key:       %s (%d bits)\n", cert.PublicKeyAlgorithm, cert.PublicKeyBits)
		}
		if cert.SignatureAlgorithm != "" {
			_, _ = fmt.Fprintf(w, "  Signature Alg:    %s\n", cert.SignatureAlgorithm)
		}
		if cert.ChainLength > 0 {
			_, _ = fmt.Fprintf(w, "  Chain Length:     %d\n", cert.ChainLength)
		}
		if len(cert.DNSNames) > 0 {
			_, _ = fmt.Fprintf(w, "  DNS Names:        %s\n", strings.Join(cert.DNSNames, ", "))
		}
	}

	if len(r.Status.CipherSuites) > 0 {
		_, _ = fmt.Fprintf(w, "\nCipher Suites:\n")
		for version, suites := range r.Status.CipherSuites {
			_, _ = fmt.Fprintf(w, "  %s:\n", version)
			for _, suite := range suites {
				grade := "?"
				if r.Status.CipherStrengthGrades != nil {
					if g, ok := r.Status.CipherStrengthGrades[suite]; ok {
						grade = g
					}
				}
				_, _ = fmt.Fprintf(w, "    - %s [%s]\n", suite, grade)
			}
		}
	}

	if len(r.Status.KeyExchangeTypes) > 0 {
		_, _ = fmt.Fprintf(w, "\nKey Exchange Types:\n")
		for kex, info := range r.Status.KeyExchangeTypes {
			_, _ = fmt.Fprintf(w, "  %s: %s\n", kex, info)
		}
	}

	if len(r.Status.ALPNProtocols) > 0 {
		_, _ = fmt.Fprintf(w, "\nALPN Protocols:\n")
		for version, proto := range r.Status.ALPNProtocols {
			_, _ = fmt.Fprintf(w, "  %s: %s\n", version, proto)
		}
	}

	if len(r.Status.NegotiatedCurves) > 0 {
		_, _ = fmt.Fprintf(w, "\nNegotiated Curves:\n")
		for curve, info := range r.Status.NegotiatedCurves {
			_, _ = fmt.Fprintf(w, "  %s: %s\n", curve, info)
		}
	}

	if r.Status.TLSAdherence != "" {
		_, _ = fmt.Fprintf(w, "\nTLS Security Profile:\n")
		_, _ = fmt.Fprintf(w, "  Adherence: %s\n", r.Status.TLSAdherence)
	}

	printProfileCompliance(w, "Ingress", r.Status.IngressProfileCompliance)
	printProfileCompliance(w, "API Server", r.Status.APIServerProfileCompliance)
	printProfileCompliance(w, "Kubelet", r.Status.KubeletProfileCompliance)

	printConditions(w, r.Status.Conditions)

	_, _ = fmt.Fprintf(w, "\nScan Info:\n")
	if r.Status.FirstSeenAt != nil {
		_, _ = fmt.Fprintf(w, "  First Seen:         %s\n", r.Status.FirstSeenAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if r.Status.LastSeenAt != nil {
		_, _ = fmt.Fprintf(w, "  Last Seen:          %s\n", r.Status.LastSeenAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if r.Status.LastCheckAt != nil {
		_, _ = fmt.Fprintf(w, "  Last Check:         %s\n", r.Status.LastCheckAt.Format("2006-01-02 15:04:05 UTC"))
	}
	_, _ = fmt.Fprintf(w, "  Check Count:        %d\n", r.Status.CheckCount)
	if r.Status.ScanDuration != "" {
		_, _ = fmt.Fprintf(w, "  Scan Duration:      %s\n", r.Status.ScanDuration)
	}
	_, _ = fmt.Fprintf(w, "  Consecutive Errors: %d\n", r.Status.ConsecutiveErrors)
	if r.Status.RetryCount > 0 {
		_, _ = fmt.Fprintf(w, "  Retry Count:        %d\n", r.Status.RetryCount)
	}
	if r.Status.NextRetryAt != nil {
		_, _ = fmt.Fprintf(w, "  Next Retry:         %s\n", r.Status.NextRetryAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if r.Status.LastError != "" {
		_, _ = fmt.Fprintf(w, "  Last Error:         %s\n", r.Status.LastError)
	}

	return nil
}

func printProfileCompliance(w *os.File, name string, result *securityv1alpha1.TLSProfileComplianceResult) {
	if result == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s TLS Profile Compliance:\n", name)
	_, _ = fmt.Fprintf(w, "  Profile:   %s\n", result.ProfileType)
	_, _ = fmt.Fprintf(w, "  Compliant: %v\n", result.Compliant)
	if len(result.DisallowedCiphers) > 0 {
		_, _ = fmt.Fprintf(w, "  Disallowed Ciphers: %v\n", result.DisallowedCiphers)
	}
	if len(result.DisallowedGroups) > 0 {
		_, _ = fmt.Fprintf(w, "  Disallowed Groups: %v\n", result.DisallowedGroups)
	}
}
