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
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	rootCmd.AddCommand(newGetCmd())
	rootCmd.AddCommand(newDescribeCmd())
	rootCmd.AddCommand(newRescanCmd())
	rootCmd.AddCommand(newTargetCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newCompletionCmd())

	registerFlagCompletions(rootCmd)

	return rootCmd
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

func registerFlagCompletions(rootCmd *cobra.Command) {
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
	_ = rootCmd.RegisterFlagCompletionFunc("tls-version", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"1.0", "1.1", "1.2", "1.3", "ssl3.0"}, cobra.ShellCompDirectiveNoFileComp
	})
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
