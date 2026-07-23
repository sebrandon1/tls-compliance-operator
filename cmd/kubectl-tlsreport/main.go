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
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

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
	filterOpts         export.FilterOptions
	sortBy             string
	kubeconfig         string
	kubecontext        string
	labelSelector      string
	outputFormat       string
	failOnNonCompliant bool
)

type exitCodeError struct {
	code int
}

func (e exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

func checkExitCode(reports []securityv1alpha1.TLSComplianceReport) error {
	if failOnNonCompliant && export.HasNonCompliantReports(reports) {
		return exitCodeError{code: 1}
	}
	return nil
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var ece exitCodeError
		if errors.As(err, &ece) {
			os.Exit(ece.code)
		}
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "kubectl-tlsreport [csv|json|yaml|junit|markdown|md]",
		Short: "Export TLS compliance reports from the cluster",
		Long: `Export TLS compliance reports from the cluster in various formats.

Supported formats: csv (default), json, yaml, junit, markdown (or md)

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
	rootCmd.PersistentFlags().StringVar(&filterOpts.TLSVersion, "tls-version", "", "Filter by TLS version support (1.0, 1.1, 1.2, 1.3, ssl3.0)")
	rootCmd.PersistentFlags().StringVar(&sortBy, "sort-by", "", "Sort results by field (host, port, compliance, expiry, grade, pqc)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to the kubeconfig file to use")
	rootCmd.PersistentFlags().StringVar(&kubecontext, "context", "", "The kubeconfig context to use")
	rootCmd.PersistentFlags().StringVarP(&labelSelector, "selector", "l", "", "Label selector to filter reports (e.g. host-network=true)")
	rootCmd.PersistentFlags().BoolVar(&failOnNonCompliant, "fail-on-non-compliant", false,
		"Exit with code 1 if any non-compliant endpoints are found (NonCompliant, NoTLS, PlaintextHTTP)")

	rootCmd.AddCommand(newSummaryCmd())
	getCmd := newGetCmd()
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(newDescribeCmd())
	rootCmd.AddCommand(newRescanCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newCompletionCmd())

	registerFlagCompletions(rootCmd, getCmd)

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
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, wide, json, yaml")

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
	case "csv", "json", "yaml", "junit", "markdown", "md":
	default:
		return fmt.Errorf("unknown format: %s (supported: csv, json, yaml, junit, markdown, md)", format)
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

	var writeErr error
	switch format {
	case "csv":
		writeErr = export.WriteCSV(os.Stdout, reports)
	case "json":
		writeErr = export.WriteJSON(os.Stdout, reports)
	case "yaml":
		writeErr = export.WriteYAML(os.Stdout, reports)
	case "junit":
		writeErr = export.WriteJUnit(os.Stdout, reports)
	case "markdown", "md":
		writeErr = export.WriteMarkdown(os.Stdout, reports)
	}
	if writeErr != nil {
		return writeErr
	}

	return checkExitCode(reports)
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

	if len(reports) == 0 {
		return printNoResourcesFound()
	}

	export.SortReports(reports, sortBy)

	if err := export.WriteSummary(os.Stdout, reports); err != nil {
		return err
	}
	return checkExitCode(reports)
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
				matched := []securityv1alpha1.TLSComplianceReport{r}
				if err := outputReports(matched); err != nil {
					return err
				}
				return checkExitCode(matched)
			}
		}
		return fmt.Errorf("report %q not found", name)
	}

	reports, err = export.FilterReports(reports, filterOpts)
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
	_, _ = fmt.Fprintln(w, "NAME\tHOST\tPORT\tSOURCE\tSTATUS\tTLS 1.2\tTLS 1.3\tPQC\tMLKEM\tGRADE")
	for _, r := range reports {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Name,
			r.Spec.Host,
			r.Spec.Port,
			string(r.Spec.SourceKind),
			string(r.Status.ComplianceStatus),
			boolDash(r.Status.TLSVersions.TLS12),
			boolDash(r.Status.TLSVersions.TLS13),
			string(r.Status.PQCReadiness),
			boolDash(r.Status.MLKEMSupported),
			r.Status.OverallCipherGrade,
		)
	}
	return w.Flush()
}

func printReportTableWide(reports []securityv1alpha1.TLSComplianceReport) error {
	if len(reports) == 0 {
		return printNoResourcesFound()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tHOST\tPORT\tSOURCE\tNAMESPACE\tSTATUS\tTLS 1.2\tTLS 1.3\tPQC\tMLKEM\tGRADE\tISSUER\tEXPIRY")
	for _, r := range reports {
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

		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Name,
			r.Spec.Host,
			r.Spec.Port,
			string(r.Spec.SourceKind),
			r.Spec.SourceNamespace,
			string(r.Status.ComplianceStatus),
			boolDash(r.Status.TLSVersions.TLS12),
			boolDash(r.Status.TLSVersions.TLS13),
			string(r.Status.PQCReadiness),
			boolDash(r.Status.MLKEMSupported),
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

func printNoResourcesFound() error {
	if filterOpts.Namespace != "" {
		fmt.Fprintf(os.Stderr, "No resources found in namespace %q.\n", filterOpts.Namespace)
	} else {
		fmt.Fprintln(os.Stderr, "No resources found.")
	}
	return nil
}

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for kubectl-tlsreport.

To load completions:

Bash:
  source <(kubectl-tlsreport completion bash)

Zsh:
  source <(kubectl-tlsreport completion zsh)

Fish:
  kubectl-tlsreport completion fish | source

PowerShell:
  kubectl-tlsreport completion powershell | Out-String | Invoke-Expression`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	}
}

func registerFlagCompletions(rootCmd, getCmd *cobra.Command) {
	_ = rootCmd.RegisterFlagCompletionFunc("status", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			string(securityv1alpha1.ComplianceStatusCompliant),
			string(securityv1alpha1.ComplianceStatusNonCompliant),
			string(securityv1alpha1.ComplianceStatusWarning),
			string(securityv1alpha1.ComplianceStatusUnreachable),
			string(securityv1alpha1.ComplianceStatusTimeout),
			string(securityv1alpha1.ComplianceStatusClosed),
			string(securityv1alpha1.ComplianceStatusFiltered),
			string(securityv1alpha1.ComplianceStatusNoTLS),
			string(securityv1alpha1.ComplianceStatusPlaintextHTTP),
			string(securityv1alpha1.ComplianceStatusMutualTLSRequired),
			string(securityv1alpha1.ComplianceStatusPending),
			string(securityv1alpha1.ComplianceStatusUnknown),
		}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = rootCmd.RegisterFlagCompletionFunc("source", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			string(securityv1alpha1.SourceKindService),
			string(securityv1alpha1.SourceKindIngress),
			string(securityv1alpha1.SourceKindRoute),
			string(securityv1alpha1.SourceKindTarget),
			string(securityv1alpha1.SourceKindPod),
			string(securityv1alpha1.SourceKindHTTPRoute),
			string(securityv1alpha1.SourceKindTLSRoute),
			string(securityv1alpha1.SourceKindGateway),
		}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = rootCmd.RegisterFlagCompletionFunc("pqc-status", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			string(securityv1alpha1.PQCReadinessPQCReady),
			string(securityv1alpha1.PQCReadinessTLS13Capable),
			string(securityv1alpha1.PQCReadinessLegacyTLS),
			string(securityv1alpha1.PQCReadinessNoPQC),
		}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = rootCmd.RegisterFlagCompletionFunc("sort-by", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"host", "port", "compliance", "expiry", "grade", "pqc"}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = getCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"table", "wide", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp
	})
}

func boolDash(b bool) string {
	if b {
		return "true"
	}
	return "-"
}

const rescanAnnotation = "tls-compliance.telco.openshift.io/rescan"

func newRescanCmd() *cobra.Command {
	var waitFlag bool
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "rescan <name>",
		Short: "Trigger an immediate rescan of a TLS compliance report",
		Example: `  # Rescan a specific report
  kubectl tlsreport rescan my-service-443-abc12345

  # Rescan and wait for completion
  kubectl tlsreport rescan my-service-443-abc12345 --wait`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runRescan(args[0], waitFlag, timeout)
		},
	}
	cmd.Flags().BoolVar(&waitFlag, "wait", false, "Wait for the rescan to complete")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "Timeout when waiting for rescan completion")
	return cmd
}

func runRescan(name string, wait bool, timeout time.Duration) error {
	c, err := buildClient()
	if err != nil {
		return err
	}

	var report securityv1alpha1.TLSComplianceReport
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, &report); err != nil {
		return fmt.Errorf("report %q not found: %w", name, err)
	}

	if report.Annotations == nil {
		report.Annotations = make(map[string]string)
	}
	report.Annotations[rescanAnnotation] = time.Now().UTC().Format(time.RFC3339)
	if err := c.Update(context.Background(), &report); err != nil {
		return fmt.Errorf("triggering rescan: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Rescan triggered for %s\n", name)

	if !wait {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for rescan to complete")
		case <-time.After(2 * time.Second):
			var updated securityv1alpha1.TLSComplianceReport
			if err := c.Get(ctx, client.ObjectKey{Name: name}, &updated); err != nil {
				return fmt.Errorf("checking rescan status: %w", err)
			}
			if _, hasAnnotation := updated.Annotations[rescanAnnotation]; !hasAnnotation {
				fmt.Fprintf(os.Stderr, "Rescan complete for %s (status: %s)\n", name, updated.Status.ComplianceStatus)
				return nil
			}
		}
	}
}

func buildClient() (client.Client, error) {
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
	return c, nil
}

func fetchReports() ([]securityv1alpha1.TLSComplianceReport, error) {
	c, err := buildClient()
	if err != nil {
		return nil, err
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
