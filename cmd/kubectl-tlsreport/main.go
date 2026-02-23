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

	"github.com/spf13/cobra"
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

var filterOpts export.FilterOptions

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "kubectl-tlsreport [csv|json|junit]",
		Short: "Export TLS compliance reports from the cluster",
		Long: `Export TLS compliance reports from the cluster in various formats.

Supported formats: csv (default), json, junit`,
		Args:          cobra.MaximumNArgs(1),
		RunE:          runExport,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVarP(&filterOpts.Namespace, "namespace", "n", "", "Filter by source namespace")
	rootCmd.PersistentFlags().StringVar(&filterOpts.Status, "status", "", "Filter by compliance status (e.g. Compliant, NonCompliant)")
	rootCmd.PersistentFlags().StringVar(&filterOpts.Source, "source", "", "Filter by source kind (e.g. Service, Ingress, Route, Pod)")

	rootCmd.AddCommand(newSummaryCmd())

	return rootCmd
}

func newSummaryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "summary",
		Short: "Show a compliance summary of all TLS endpoints",
		RunE:  runSummary,
	}
}

func runExport(cmd *cobra.Command, args []string) error {
	format := "csv"
	if len(args) > 0 {
		format = args[0]
	}

	switch format {
	case "csv", "json", "junit":
	default:
		return fmt.Errorf("unknown format: %s (supported: csv, json, junit)", format)
	}

	reports, err := fetchReports()
	if err != nil {
		return err
	}

	reports = export.FilterReports(reports, filterOpts)

	switch format {
	case "csv":
		return export.WriteCSV(os.Stdout, reports)
	case "json":
		return export.WriteJSON(os.Stdout, reports)
	case "junit":
		return export.WriteJUnit(os.Stdout, reports)
	}

	return nil
}

func runSummary(_ *cobra.Command, _ []string) error {
	reports, err := fetchReports()
	if err != nil {
		return err
	}

	reports = export.FilterReports(reports, filterOpts)

	return export.WriteSummary(os.Stdout, reports)
}

func fetchReports() ([]securityv1alpha1.TLSComplianceReport, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building kubeconfig: %w", err)
	}

	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	var reportList securityv1alpha1.TLSComplianceReportList
	if err := c.List(context.Background(), &reportList); err != nil {
		return nil, fmt.Errorf("listing TLSComplianceReports: %w", err)
	}

	return reportList.Items, nil
}
