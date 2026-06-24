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
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

var version = "dev"

var (
	filterOpts    export.FilterOptions
	sortBy        string
	kubeconfig    string
	kubecontext   string
	labelSelector string
	outputFormat  string
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "kubectl-tlsreport [csv|json|junit|markdown|md]",
		Short: "Export TLS compliance reports from the cluster",
		Long: `Export TLS compliance reports from the cluster in various formats.

Supported formats: csv (default), json, junit, markdown (or md)

Use --kubeconfig and --context to target a specific cluster.`,
		Args:          cobra.MaximumNArgs(1),
		RunE:          runExport,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVarP(&filterOpts.Namespace, "namespace", "n", "", "Filter by source namespace")
	rootCmd.PersistentFlags().StringVar(&filterOpts.Status, "status", "", "Filter by compliance status (e.g. Compliant, NonCompliant)")
	rootCmd.PersistentFlags().StringVar(&filterOpts.Source, "source", "", "Filter by source kind (e.g. Service, Ingress, Route, Pod)")
	rootCmd.PersistentFlags().StringVar(&filterOpts.PQCStatus, "pqc-status", "", "Filter by PQC readiness (PQCReady, TLS13Capable, LegacyTLS, NoPQC)")
	rootCmd.PersistentFlags().StringVar(&filterOpts.ExpiresWithin, "expires-within", "", "Show certs expiring within duration (e.g. 30d, 7d, 90d)")
	rootCmd.PersistentFlags().BoolVar(&filterOpts.Expired, "expired", false, "Show only expired certificates")
	rootCmd.PersistentFlags().StringVar(&filterOpts.Issuer, "cert-issuer", "", "Filter by certificate issuer (substring match)")
	rootCmd.PersistentFlags().StringVar(&filterOpts.Subject, "cert-subject", "", "Filter by certificate subject (substring match)")
	rootCmd.PersistentFlags().StringVar(&sortBy, "sort-by", "", "Sort results by field (host, port, compliance, expiry, grade, pqc)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to the kubeconfig file to use")
	rootCmd.PersistentFlags().StringVar(&kubecontext, "context", "", "The kubeconfig context to use")
	rootCmd.PersistentFlags().StringVarP(&labelSelector, "selector", "l", "", "Label selector to filter reports (e.g. host-network=true)")

	rootCmd.AddCommand(newSummaryCmd())
	rootCmd.AddCommand(newGetCmd())
	rootCmd.AddCommand(newDescribeCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

func newSummaryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "summary",
		Short: "Show a compliance summary of all TLS endpoints",
		Example: `  # Show summary of all endpoints
  kubectl tlsreport summary

  # Show summary for a specific namespace
  kubectl tlsreport summary -n production`,
		RunE: runSummary,
	}
}

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
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, wide, json")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the plugin version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("kubectl-tlsreport " + version)
		},
	}
}

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

func runExport(cmd *cobra.Command, args []string) error {
	format := "csv"
	if len(args) > 0 {
		format = args[0]
	}

	switch format {
	case "csv", "json", "junit", "markdown", "md":
	default:
		return fmt.Errorf("unknown format: %s (supported: csv, json, junit, markdown, md)", format)
	}

	reports, err := fetchReports()
	if err != nil {
		return err
	}

	reports, err = export.FilterReports(reports, filterOpts)
	if err != nil {
		return err
	}

	export.SortReports(reports, sortBy)

	switch format {
	case "csv":
		return export.WriteCSV(os.Stdout, reports)
	case "json":
		return export.WriteJSON(os.Stdout, reports)
	case "junit":
		return export.WriteJUnit(os.Stdout, reports)
	case "markdown", "md":
		return export.WriteMarkdown(os.Stdout, reports)
	}

	return nil
}

func runSummary(_ *cobra.Command, _ []string) error {
	reports, err := fetchReports()
	if err != nil {
		return err
	}

	reports, err = export.FilterReports(reports, filterOpts)
	if err != nil {
		return err
	}

	export.SortReports(reports, sortBy)

	return export.WriteSummary(os.Stdout, reports)
}

func runGet(_ *cobra.Command, args []string) error {
	reports, err := fetchReports()
	if err != nil {
		return err
	}

	if len(args) > 0 {
		name := args[0]
		for _, r := range reports {
			if r.Name == name {
				return outputReports([]securityv1alpha1.TLSComplianceReport{r})
			}
		}
		return fmt.Errorf("report %q not found", name)
	}

	reports, err = export.FilterReports(reports, filterOpts)
	if err != nil {
		return err
	}

	export.SortReports(reports, sortBy)

	return outputReports(reports)
}

func outputReports(reports []securityv1alpha1.TLSComplianceReport) error {
	switch outputFormat {
	case "json":
		return export.WriteJSON(os.Stdout, reports)
	case "wide":
		return printReportTableWide(reports)
	case "table", "":
		return printReportTable(reports)
	default:
		return fmt.Errorf("unknown output format: %s (supported: table, wide, json)", outputFormat)
	}
}

func printReportTable(reports []securityv1alpha1.TLSComplianceReport) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tHOST\tPORT\tSOURCE\tSTATUS\tTLS 1.2\tTLS 1.3\tPQC\tGRADE")
	for _, r := range reports {
		tls12 := "-"
		tls13 := "-"
		if r.Status.TLSVersions.TLS12 {
			tls12 = "true"
		}
		if r.Status.TLSVersions.TLS13 {
			tls13 = "true"
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Name,
			r.Spec.Host,
			r.Spec.Port,
			string(r.Spec.SourceKind),
			string(r.Status.ComplianceStatus),
			tls12, tls13,
			string(r.Status.PQCReadiness),
			r.Status.OverallCipherGrade,
		)
	}
	return w.Flush()
}

func printReportTableWide(reports []securityv1alpha1.TLSComplianceReport) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tHOST\tPORT\tSOURCE\tSTATUS\tTLS 1.2\tTLS 1.3\tPQC\tGRADE\tISSUER\tEXPIRY")
	for _, r := range reports {
		tls12 := "-"
		tls13 := "-"
		if r.Status.TLSVersions.TLS12 {
			tls12 = "true"
		}
		if r.Status.TLSVersions.TLS13 {
			tls13 = "true"
		}

		issuer := "-"
		expiry := "-"
		if r.Status.CertificateInfo != nil {
			if r.Status.CertificateInfo.Issuer != "" {
				issuer = r.Status.CertificateInfo.Issuer
			}
			if r.Status.CertificateInfo.NotAfter != nil {
				expiry = r.Status.CertificateInfo.NotAfter.Format("2006-01-02")
			}
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Name,
			r.Spec.Host,
			r.Spec.Port,
			string(r.Spec.SourceKind),
			string(r.Status.ComplianceStatus),
			tls12, tls13,
			string(r.Status.PQCReadiness),
			r.Status.OverallCipherGrade,
			issuer,
			expiry,
		)
	}
	return w.Flush()
}

func runDescribe(_ *cobra.Command, args []string) error {
	reports, err := fetchReports()
	if err != nil {
		return err
	}

	name := args[0]
	for _, r := range reports {
		if r.Name == name {
			return printReportDetail(r)
		}
	}
	return fmt.Errorf("report %q not found", name)
}

func printReportDetail(r securityv1alpha1.TLSComplianceReport) error {
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

	if len(r.Status.NegotiatedCurves) > 0 {
		_, _ = fmt.Fprintf(w, "\nNegotiated Curves:\n")
		for curve, info := range r.Status.NegotiatedCurves {
			_, _ = fmt.Fprintf(w, "  %s: %s\n", curve, info)
		}
	}

	if r.Status.IngressProfileCompliance != nil {
		_, _ = fmt.Fprintf(w, "\nIngress TLS Profile Compliance:\n")
		_, _ = fmt.Fprintf(w, "  Profile:   %s\n", r.Status.IngressProfileCompliance.ProfileType)
		_, _ = fmt.Fprintf(w, "  Compliant: %v\n", r.Status.IngressProfileCompliance.Compliant)
	}
	if r.Status.APIServerProfileCompliance != nil {
		_, _ = fmt.Fprintf(w, "\nAPI Server TLS Profile Compliance:\n")
		_, _ = fmt.Fprintf(w, "  Profile:   %s\n", r.Status.APIServerProfileCompliance.ProfileType)
		_, _ = fmt.Fprintf(w, "  Compliant: %v\n", r.Status.APIServerProfileCompliance.Compliant)
	}
	if r.Status.KubeletProfileCompliance != nil {
		_, _ = fmt.Fprintf(w, "\nKubelet TLS Profile Compliance:\n")
		_, _ = fmt.Fprintf(w, "  Profile:   %s\n", r.Status.KubeletProfileCompliance.ProfileType)
		_, _ = fmt.Fprintf(w, "  Compliant: %v\n", r.Status.KubeletProfileCompliance.Compliant)
	}

	if len(r.Status.Conditions) > 0 {
		_, _ = fmt.Fprintf(w, "\nConditions:\n")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  TYPE\tSTATUS\tREASON\tMESSAGE")
		for _, c := range r.Status.Conditions {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", c.Type, c.Status, c.Reason, c.Message)
		}
		_ = tw.Flush()
	}

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

func fetchReports() ([]securityv1alpha1.TLSComplianceReport, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	configOverrides := &clientcmd.ConfigOverrides{}
	if kubecontext != "" {
		configOverrides.CurrentContext = kubecontext
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building kubeconfig: %w", err)
	}

	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	listOpts := []client.ListOption{}
	if labelSelector != "" {
		sel, err := labels.Parse(labelSelector)
		if err != nil {
			return nil, fmt.Errorf("parsing label selector: %w", err)
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: sel})
	}

	var reportList securityv1alpha1.TLSComplianceReportList
	if err := c.List(context.Background(), &reportList, listOpts...); err != nil {
		return nil, fmt.Errorf("listing TLSComplianceReports: %w", err)
	}

	return reportList.Items, nil
}
