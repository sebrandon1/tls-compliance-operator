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
	"text/tabwriter"

	"github.com/spf13/cobra"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [name]",
		Short: "Display TLS compliance reports in a table",
		Example: `  # List all reports
  kubectl tlsreport get

  # Get reports as JSON
  kubectl tlsreport get -o json

  # Get reports with extra columns
  kubectl tlsreport get -o wide

  # Get a specific report
  kubectl tlsreport get my-service-443-abc12345

  # Get non-compliant endpoints in a namespace
  kubectl tlsreport get --status NonCompliant -n production`,
		RunE: runGet,
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, wide, json, yaml")
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"table", "wide", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func runGet(cmd *cobra.Command, args []string) error {
	reports, err := fetchReports(cmd.Context())
	if err != nil {
		return err
	}

	if len(args) > 0 {
		name := args[0]
		for i := range reports {
			if reports[i].Name == name {
				matched := []securityv1alpha1.TLSComplianceReport{reports[i]}
				if err := outputReports(matched); err != nil {
					return err
				}
				return checkExitCode(matched)
			}
		}
		return fmt.Errorf("report %q not found", name)
	}

	reports, err = export.FilterReports(reports, &filterOpts)
	if err != nil {
		return err
	}

	export.SortReports(reports, sortBy)

	if err := outputReports(reports); err != nil {
		return err
	}
	return checkExitCode(reports)
}

func outputReports(reports []securityv1alpha1.TLSComplianceReport) error {
	switch outputFormat {
	case "json":
		return export.WriteJSON(os.Stdout, reports)
	case "yaml":
		return export.WriteYAML(os.Stdout, reports)
	case "wide":
		return printReportTableWide(reports)
	case "table", "":
		return printReportTable(reports)
	default:
		return fmt.Errorf("unknown output format: %s (supported: table, wide, json, yaml)", outputFormat)
	}
}

func printReportTable(reports []securityv1alpha1.TLSComplianceReport) error {
	if len(reports) == 0 {
		return printNoResourcesFound()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tHOST\tPORT\tSOURCE\tCOMPLIANCE\tGRADE\tFS\tTLS 1.3\tTLS 1.2\tPQC\tMLKEM")
	for i := range reports {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			reports[i].Name,
			reports[i].Spec.Host,
			reports[i].Spec.Port,
			string(reports[i].Spec.SourceKind),
			string(reports[i].Status.ComplianceStatus),
			reports[i].Status.OverallCipherGrade,
			boolDash(reports[i].Status.ForwardSecrecy),
			boolDash(reports[i].Status.TLSVersions.TLS13),
			boolDash(reports[i].Status.TLSVersions.TLS12),
			string(reports[i].Status.PQCReadiness),
			boolDash(reports[i].Status.MLKEMSupported),
		)
	}
	return w.Flush()
}

func printReportTableWide(reports []securityv1alpha1.TLSComplianceReport) error {
	if len(reports) == 0 {
		return printNoResourcesFound()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tHOST\tPORT\tSOURCE\tNAMESPACE\tCOMPLIANCE\tGRADE\tFS\tTLS 1.3\tTLS 1.2\tTLS 1.0\tSSL 3.0\tPQC\tMLKEM\tISSUER\tCERT EXPIRY")
	for i := range reports {
		issuer := "-"
		expiry := "-"
		if reports[i].Status.CertificateInfo != nil {
			if reports[i].Status.CertificateInfo.Issuer != "" {
				issuer = reports[i].Status.CertificateInfo.Issuer
			}
			if reports[i].Status.CertificateInfo.NotAfter != nil {
				expiry = reports[i].Status.CertificateInfo.NotAfter.Format("2006-01-02")
			}
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			reports[i].Name,
			reports[i].Spec.Host,
			reports[i].Spec.Port,
			string(reports[i].Spec.SourceKind),
			reports[i].Spec.SourceNamespace,
			string(reports[i].Status.ComplianceStatus),
			reports[i].Status.OverallCipherGrade,
			boolDash(reports[i].Status.ForwardSecrecy),
			boolDash(reports[i].Status.TLSVersions.TLS13),
			boolDash(reports[i].Status.TLSVersions.TLS12),
			boolDash(reports[i].Status.TLSVersions.TLS10),
			boolDash(reports[i].Status.TLSVersions.SSL30),
			string(reports[i].Status.PQCReadiness),
			boolDash(reports[i].Status.MLKEMSupported),
			issuer,
			expiry,
		)
	}
	return w.Flush()
}

func boolDash(b bool) string {
	if b {
		return "true"
	}
	return "-"
}
