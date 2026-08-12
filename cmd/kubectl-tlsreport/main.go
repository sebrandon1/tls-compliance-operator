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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

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
	targetOutputFormat string
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		var ece exitCodeError
		if errors.As(err, &ece) {
			os.Exit(ece.code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
	rootCmd.PersistentFlags().StringVar(&filterOpts.Grade, "grade", "", "Filter by exact cipher grade (A, B, C, D, F)")
	rootCmd.PersistentFlags().StringVar(&filterOpts.MinGrade, "min-grade", "", "Filter by minimum cipher grade (e.g. B shows A and B)")
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
	rootCmd.AddCommand(newTargetCmd())
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

	reports, err := fetchReports(cmd.Context())
	if err != nil {
		return err
	}

	reports, err = export.FilterReports(reports, &filterOpts)
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

func runSummary(cmd *cobra.Command, _ []string) error {
	reports, err := fetchReports(cmd.Context())
	if err != nil {
		return err
	}

	reports, err = export.FilterReports(reports, &filterOpts)
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

func newTargetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage TLSComplianceTarget resources",
	}
	cmd.AddCommand(newTargetListCmd())
	cmd.AddCommand(newTargetGetCmd())
	cmd.AddCommand(newTargetDescribeCmd())
	cmd.AddCommand(newTargetCreateCmd())
	cmd.AddCommand(newTargetDeleteCmd())
	return cmd
}

func newTargetListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all TLSComplianceTargets",
		Example: `  # List targets in table format
  kubectl tlsreport target list

  # List targets with additional details
  kubectl tlsreport target list -o wide

  # Output as JSON for scripting
  kubectl tlsreport target list -o json

  # Output as YAML
  kubectl tlsreport target list -o yaml`,
		RunE: runTargetList,
	}
	cmd.Flags().StringVarP(&targetOutputFormat, "output", "o", "table", "Output format: table, wide, json, yaml")
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"table", "wide", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func newTargetGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Get a TLSComplianceTarget by name",
		Example: `  # Get a target in table format
  kubectl tlsreport target get google-com-443

  # Get a target as JSON
  kubectl tlsreport target get google-com-443 -o json

  # Get a target as YAML
  kubectl tlsreport target get google-com-443 -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: runTargetGet,
	}
	cmd.Flags().StringVarP(&targetOutputFormat, "output", "o", "table", "Output format: table, wide, json, yaml")
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"table", "wide", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func newTargetDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <name>",
		Short: "Show detailed information about a TLSComplianceTarget",
		Example: `  # Describe a specific target
  kubectl tlsreport target describe google-com-443`,
		Args: cobra.ExactArgs(1),
		RunE: runTargetDescribe,
	}
}

func newTargetCreateCmd() *cobra.Command {
	var waitFlag bool
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "create <host> <port>",
		Short: "Create a TLSComplianceTarget for the given host and port",
		Example: `  # Create a target
  kubectl tlsreport target create google.com 443

  # Create a target and wait for the scan result
  kubectl tlsreport target create google.com 443 --wait

  # Create with a custom timeout
  kubectl tlsreport target create google.com 443 --wait --timeout 120s`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTargetCreate(cmd, args, waitFlag, timeout)
		},
	}
	cmd.Flags().BoolVar(&waitFlag, "wait", false, "Wait for the scan to complete and display the result")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "Timeout when waiting for scan completion")
	return cmd
}

func newTargetDeleteCmd() *cobra.Command {
	var deleteAll bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a TLSComplianceTarget by name",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTargetDelete(cmd.Context(), args, deleteAll)
		},
	}
	cmd.Flags().BoolVar(&deleteAll, "all", false, "Delete all TLSComplianceTargets")
	return cmd
}

func runTargetList(cmd *cobra.Command, _ []string) error {
	targets, err := fetchTargets(cmd.Context())
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "No targets found.")
		return nil
	}
	return outputTargets(targets)
}

func outputTargets(targets []securityv1alpha1.TLSComplianceTarget) error {
	switch targetOutputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(targets)
	case "yaml":
		for i := range targets {
			ydata, err := sigsyaml.Marshal(targets[i])
			if err != nil {
				return fmt.Errorf("marshalling target %s to YAML: %w", targets[i].Name, err)
			}
			if i > 0 {
				fmt.Fprintln(os.Stdout, "---")
			}
			fmt.Fprint(os.Stdout, string(ydata))
		}
		return nil
	case "wide":
		return printTargetTableWide(targets)
	case "table", "":
		return printTargetTable(targets)
	default:
		return fmt.Errorf("unknown output format: %s (supported: table, wide, json, yaml)", targetOutputFormat)
	}
}

func printTargetTable(targets []securityv1alpha1.TLSComplianceTarget) error {
	return printTargetTableImpl(targets, false)
}

func printTargetTableWide(targets []securityv1alpha1.TLSComplianceTarget) error {
	return printTargetTableImpl(targets, true)
}

func printTargetTableImpl(targets []securityv1alpha1.TLSComplianceTarget, wide bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	header := "NAME\tHOST\tPORT\tSTATUS\tREPORT"
	if wide {
		header += "\tMESSAGE"
	}
	header += "\tLAST SCANNED\tAGE"
	_, _ = fmt.Fprintln(w, header)
	for i := range targets {
		lastScanned := "-"
		if targets[i].Status.LastScannedAt != nil {
			lastScanned = targets[i].Status.LastScannedAt.Format("2006-01-02T15:04:05Z")
		}
		report := targets[i].Status.ReportName
		if report == "" {
			report = "-"
		}
		age := formatAge(time.Since(targets[i].CreationTimestamp.Time))
		row := fmt.Sprintf("%s\t%s\t%d\t%s\t%s",
			targets[i].Name, targets[i].Spec.Host, targets[i].Spec.Port,
			string(targets[i].Status.ComplianceStatus), report)
		if wide {
			message := targets[i].Status.Message
			if message == "" {
				message = "-"
			}
			row += "\t" + message
		}
		row += fmt.Sprintf("\t%s\t%s", lastScanned, age)
		_, _ = fmt.Fprintln(w, row)
	}
	return w.Flush()
}

func runTargetGet(cmd *cobra.Command, args []string) error {
	c, err := buildClient()
	if err != nil {
		return err
	}
	var target securityv1alpha1.TLSComplianceTarget
	if err := c.Get(cmd.Context(), client.ObjectKey{Name: args[0]}, &target); err != nil {
		return fmt.Errorf("getting TLSComplianceTarget %q: %w", args[0], err)
	}
	return outputTargets([]securityv1alpha1.TLSComplianceTarget{target})
}

func runTargetDescribe(cmd *cobra.Command, args []string) error {
	c, err := buildClient()
	if err != nil {
		return err
	}
	var target securityv1alpha1.TLSComplianceTarget
	if err := c.Get(cmd.Context(), client.ObjectKey{Name: args[0]}, &target); err != nil {
		return fmt.Errorf("getting TLSComplianceTarget %q: %w", args[0], err)
	}
	return printTargetDetail(&target)
}

func printTargetDetail(t *securityv1alpha1.TLSComplianceTarget) error {
	w := os.Stdout

	_, _ = fmt.Fprintf(w, "Name:         %s\n", t.Name)
	_, _ = fmt.Fprintf(w, "Host:         %s\n", t.Spec.Host)
	_, _ = fmt.Fprintf(w, "Port:         %d\n", t.Spec.Port)
	_, _ = fmt.Fprintf(w, "Age:          %s\n", formatAge(time.Since(t.CreationTimestamp.Time)))

	_, _ = fmt.Fprintf(w, "\nStatus:\n")
	status := string(t.Status.ComplianceStatus)
	if status == "" {
		status = "(pending)"
	}
	_, _ = fmt.Fprintf(w, "  Compliance:    %s\n", status)
	if t.Status.ReportName != "" {
		_, _ = fmt.Fprintf(w, "  Report:        %s\n", t.Status.ReportName)
	}
	if t.Status.Message != "" {
		_, _ = fmt.Fprintf(w, "  Message:       %s\n", t.Status.Message)
	}
	if t.Status.LastScannedAt != nil {
		_, _ = fmt.Fprintf(w, "  Last Scanned:  %s\n", t.Status.LastScannedAt.Format("2006-01-02 15:04:05 UTC"))
	}

	printConditions(w, t.Status.Conditions)

	return nil
}

func printConditions(w *os.File, conditions []metav1.Condition) {
	if len(conditions) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\nConditions:\n")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  TYPE\tSTATUS\tREASON\tMESSAGE")
	for _, c := range conditions {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", c.Type, c.Status, c.Reason, c.Message)
	}
	_ = tw.Flush()
}

func runTargetCreate(cmd *cobra.Command, args []string, wait bool, timeout time.Duration) error {
	host := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q: must be 1-65535", args[1])
	}

	c, err := buildClient()
	if err != nil {
		return err
	}

	sanitized := strings.ToLower(host)
	sanitized = strings.NewReplacer(".", "-", ":", "-").Replace(sanitized)
	name := fmt.Sprintf("%s-%d", sanitized, port)

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: securityv1alpha1.TLSComplianceTargetSpec{
			Host: host,
			Port: int32(port),
		},
	}

	if err := c.Create(cmd.Context(), target); err != nil {
		return fmt.Errorf("creating target: %w", err)
	}

	fmt.Fprintf(os.Stderr, "tlscompliancetarget/%s created\n", name)

	if !wait {
		return nil
	}

	return waitForTargetScan(cmd.Context(), c, name, timeout)
}

func waitForTargetScan(ctx context.Context, c client.Client, name string, timeout time.Duration) error {
	fmt.Fprint(os.Stderr, "Waiting for scan to complete...")

	waitCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	for {
		select {
		case <-waitCtx.Done():
			fmt.Fprintln(os.Stderr)
			return fmt.Errorf("timeout waiting for scan of target %s", name)
		case <-time.After(2 * time.Second):
			fmt.Fprint(os.Stderr, ".")
			var target securityv1alpha1.TLSComplianceTarget
			if err := c.Get(waitCtx, client.ObjectKey{Name: name}, &target); err != nil {
				return fmt.Errorf("checking target status: %w", err)
			}
			if target.Status.LastScannedAt != nil {
				fmt.Fprintln(os.Stderr, " done")
				status := string(target.Status.ComplianceStatus)
				fmt.Fprintf(os.Stdout, "Status: %s\n", status)
				if target.Status.ReportName != "" {
					fmt.Fprintf(os.Stdout, "Report: %s\n", target.Status.ReportName)
				}
				if target.Status.Message != "" {
					fmt.Fprintf(os.Stdout, "Message: %s\n", target.Status.Message)
				}
				return nil
			}
		}
	}
}

func runTargetDelete(ctx context.Context, args []string, deleteAll bool) error {
	if !deleteAll && len(args) == 0 {
		return fmt.Errorf("target name required (or use --all)")
	}

	c, err := buildClient()
	if err != nil {
		return err
	}

	if deleteAll {
		targets, err := fetchTargets(ctx)
		if err != nil {
			return err
		}
		for i := range targets {
			if err := c.Delete(ctx, &targets[i]); err != nil {
				return fmt.Errorf("deleting target %s: %w", targets[i].Name, err)
			}
			fmt.Fprintf(os.Stderr, "tlscompliancetarget/%s deleted\n", targets[i].Name)
		}
		return nil
	}

	target := &securityv1alpha1.TLSComplianceTarget{
		ObjectMeta: metav1.ObjectMeta{Name: args[0]},
	}
	if err := c.Delete(ctx, target); err != nil {
		return fmt.Errorf("deleting target %q: %w", args[0], err)
	}
	fmt.Fprintf(os.Stderr, "tlscompliancetarget/%s deleted\n", args[0])
	return nil
}

func fetchTargets(ctx context.Context) ([]securityv1alpha1.TLSComplianceTarget, error) {
	c, err := buildClient()
	if err != nil {
		return nil, err
	}
	var targetList securityv1alpha1.TLSComplianceTargetList
	if err := c.List(ctx, &targetList); err != nil {
		return nil, fmt.Errorf("listing TLSComplianceTargets: %w", err)
	}
	return targetList.Items, nil
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

func boolDash(b bool) string {
	if b {
		return "true"
	}
	return "-"
}

const rescanAnnotation = "tls-compliance.telco.openshift.io/rescan"

func newRescanCmd() *cobra.Command {
	var waitFlag bool
	var allFlag bool
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "rescan [name]",
		Short: "Trigger an immediate rescan of TLS compliance reports",
		Example: `  # Rescan a specific report
  kubectl tlsreport rescan my-service-443-abc12345

  # Rescan and wait for completion
  kubectl tlsreport rescan my-service-443-abc12345 --wait

  # Rescan all reports
  kubectl tlsreport rescan --all

  # Rescan all non-compliant reports
  kubectl tlsreport rescan --all --status NonCompliant

  # Rescan all reports matching a label selector
  kubectl tlsreport rescan --all -l host-network=true

  # Rescan all reports in a specific namespace
  kubectl tlsreport rescan --all -n production`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !allFlag {
				return fmt.Errorf("specify a report name or use --all to rescan all matching reports")
			}
			if len(args) > 0 && allFlag {
				return fmt.Errorf("cannot specify both a report name and --all")
			}
			if allFlag {
				return runRescanAll(cmd.Context(), waitFlag, timeout)
			}
			return runRescan(cmd.Context(), args[0], waitFlag, timeout)
		},
	}
	cmd.Flags().BoolVar(&allFlag, "all", false, "Rescan all reports matching current filters")
	cmd.Flags().BoolVar(&waitFlag, "wait", false, "Wait for the rescan to complete")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "Timeout when waiting for rescan completion")
	return cmd
}

func runRescan(ctx context.Context, name string, wait bool, timeout time.Duration) error {
	c, err := buildClient()
	if err != nil {
		return err
	}

	var report securityv1alpha1.TLSComplianceReport
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &report); err != nil {
		return fmt.Errorf("report %q not found: %w", name, err)
	}

	if err := triggerRescan(ctx, c, &report); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Rescan triggered for %s\n", name)

	if !wait {
		return nil
	}

	return waitForRescan(ctx, c, name, timeout)
}

func runRescanAll(ctx context.Context, wait bool, timeout time.Duration) error {
	c, err := buildClient()
	if err != nil {
		return err
	}

	reports, err := fetchReportsWithClient(ctx, c)
	if err != nil {
		return err
	}

	reports, err = export.FilterReports(reports, &filterOpts)
	if err != nil {
		return fmt.Errorf("filtering reports: %w", err)
	}

	return rescanReports(ctx, c, reports, wait, timeout)
}

func rescanReports(ctx context.Context, c client.Client, reports []securityv1alpha1.TLSComplianceReport, wait bool, timeout time.Duration) error {
	if len(reports) == 0 {
		fmt.Fprintln(os.Stderr, "No reports match the specified filters.")
		return nil
	}

	var triggered []string
	var triggerFailed int
	for i := range reports {
		if err := triggerRescan(ctx, c, &reports[i]); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to trigger rescan for %s: %v\n", reports[i].Name, err)
			triggerFailed++
			continue
		}
		triggered = append(triggered, reports[i].Name)
	}

	fmt.Fprintf(os.Stderr, "Rescan triggered for %d/%d reports\n", len(triggered), len(reports))

	if !wait || len(triggered) == 0 {
		if triggerFailed > 0 {
			return exitCodeError{code: 1}
		}
		return nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	completed := 0
	for _, name := range triggered {
		if err := waitForRescan(timeoutCtx, c, name, 0); err != nil {
			fmt.Fprintf(os.Stderr, "Timeout waiting for %s\n", name)
			continue
		}
		completed++
	}
	fmt.Fprintf(os.Stderr, "Rescan completed for %d/%d reports\n", completed, len(triggered))
	if triggerFailed > 0 || completed < len(triggered) {
		return exitCodeError{code: 1}
	}
	return nil
}

func triggerRescan(ctx context.Context, c client.Client, report *securityv1alpha1.TLSComplianceReport) error {
	if report.Annotations == nil {
		report.Annotations = make(map[string]string)
	}
	report.Annotations[rescanAnnotation] = time.Now().UTC().Format(time.RFC3339)
	if err := c.Update(ctx, report); err != nil {
		return fmt.Errorf("triggering rescan for %s: %w", report.Name, err)
	}
	return nil
}

func waitForRescan(ctx context.Context, c client.Client, name string, timeout time.Duration) error {
	waitCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	for {
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timeout waiting for rescan of %s", name)
		case <-time.After(2 * time.Second):
			var updated securityv1alpha1.TLSComplianceReport
			if err := c.Get(waitCtx, client.ObjectKey{Name: name}, &updated); err != nil {
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

func fetchReports(ctx context.Context) ([]securityv1alpha1.TLSComplianceReport, error) {
	c, err := buildClient()
	if err != nil {
		return nil, err
	}
	return fetchReportsWithClient(ctx, c)
}

func fetchReportsWithClient(ctx context.Context, c client.Client) ([]securityv1alpha1.TLSComplianceReport, error) {
	listOpts := []client.ListOption{}
	if labelSelector != "" {
		sel, err := labels.Parse(labelSelector)
		if err != nil {
			return nil, fmt.Errorf("parsing label selector: %w", err)
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: sel})
	}

	var reportList securityv1alpha1.TLSComplianceReportList
	if err := c.List(ctx, &reportList, listOpts...); err != nil {
		return nil, fmt.Errorf("listing TLSComplianceReports: %w", err)
	}

	return reportList.Items, nil
}
