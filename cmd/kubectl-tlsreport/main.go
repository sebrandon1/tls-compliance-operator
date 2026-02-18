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

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	format := "csv"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "csv", "junit":
			format = os.Args[1]
		case "--help", "-h":
			printUsage()
			return nil
		default:
			fmt.Fprintf(os.Stderr, "Unknown format: %s\n\n", os.Args[1])
			printUsage()
			return fmt.Errorf("unknown format: %s", os.Args[1])
		}
	}

	// Build client from kubeconfig
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("building kubeconfig: %w", err)
	}

	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// List all TLSComplianceReports (cluster-scoped)
	var reportList securityv1alpha1.TLSComplianceReportList
	if err := c.List(context.Background(), &reportList); err != nil {
		return fmt.Errorf("listing TLSComplianceReports: %w", err)
	}

	switch format {
	case "csv":
		return export.WriteCSV(os.Stdout, reportList.Items)
	case "junit":
		return export.WriteJUnit(os.Stdout, reportList.Items)
	}

	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: kubectl tlsreport [FORMAT]

Export TLS compliance reports from the cluster.

Formats:
  csv    Export as CSV (default)
  junit  Export as JUnit XML

Examples:
  kubectl tlsreport csv > report.csv
  kubectl tlsreport junit > report.xml
`)
}
