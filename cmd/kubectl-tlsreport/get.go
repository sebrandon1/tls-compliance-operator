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
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func newGetCmd() *cobra.Command {
	var watchFlag bool
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
  kubectl tlsreport get --status NonCompliant -n production

  # Watch reports as they are created or updated
  kubectl tlsreport get --watch`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(cmd, args, watchFlag)
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, wide, json, yaml")
	cmd.Flags().BoolVarP(&watchFlag, "watch", "w", false, "Watch for create, update, and delete events")
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"table", "wide", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func runGet(cmd *cobra.Command, args []string, watchFlag bool) error {
	if watchFlag {
		return runGetWatch(cmd, args)
	}

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

func runGetWatch(cmd *cobra.Command, args []string) error {
	c, err := buildClient()
	if err != nil {
		return err
	}
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	return watchReports(cmd.Context(), c, name, os.Stdout)
}

func watchReports(ctx context.Context, c client.WithWatch, name string, w io.Writer) error {
	listOpts, err := reportListOptions("")
	if err != nil {
		return err
	}

	var reportList securityv1alpha1.TLSComplianceReportList
	if err := c.List(ctx, &reportList, listOpts...); err != nil {
		return fmt.Errorf("listing TLSComplianceReports: %w", err)
	}

	reports := reportList.Items
	if name != "" {
		reports = filterReportsByName(reports, name)
	}
	reports, err = export.FilterReports(reports, &filterOpts)
	if err != nil {
		return err
	}
	export.SortReports(reports, sortBy)

	if err := writeWatchSnapshot(w, reports); err != nil {
		return err
	}

	watchOpts, err := reportListOptions(reportList.ResourceVersion)
	if err != nil {
		return err
	}
	watcher, err := c.Watch(ctx, &securityv1alpha1.TLSComplianceReportList{}, watchOpts...)
	if err != nil {
		return fmt.Errorf("watching TLSComplianceReports: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-watcher.ResultChan():
			if !ok {
				return nil
			}
			if err := handleGetWatchEvent(w, ev, name); err != nil {
				return err
			}
		}
	}
}

func handleGetWatchEvent(w io.Writer, ev watch.Event, name string) error {
	switch ev.Type {
	case watch.Added, watch.Modified, watch.Deleted:
	case watch.Bookmark, watch.Error, "":
		if ev.Type == watch.Error {
			return fmt.Errorf("watch error: %v", ev.Object)
		}
		return nil
	default:
		return nil
	}

	report, ok := ev.Object.(*securityv1alpha1.TLSComplianceReport)
	if !ok || report == nil {
		return nil
	}

	deleted := ev.Type == watch.Deleted
	if !deleted {
		match, err := reportMatchesGetFilters(report, name)
		if err != nil {
			return err
		}
		if !match {
			return nil
		}
	} else if name != "" && report.Name != name {
		return nil
	}

	return writeWatchEvent(w, report, deleted)
}

func reportMatchesGetFilters(report *securityv1alpha1.TLSComplianceReport, name string) (bool, error) {
	if name != "" && report.Name != name {
		return false, nil
	}
	filtered, err := export.FilterReports([]securityv1alpha1.TLSComplianceReport{*report}, &filterOpts)
	if err != nil {
		return false, err
	}
	return len(filtered) > 0, nil
}

func filterReportsByName(reports []securityv1alpha1.TLSComplianceReport, name string) []securityv1alpha1.TLSComplianceReport {
	for i := range reports {
		if reports[i].Name == name {
			return []securityv1alpha1.TLSComplianceReport{reports[i]}
		}
	}
	return nil
}

func writeWatchSnapshot(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	switch outputFormat {
	case "json":
		for i := range reports {
			if err := writeWatchJSON(w, &reports[i]); err != nil {
				return err
			}
		}
		return nil
	case "yaml":
		for i := range reports {
			if err := writeWatchYAML(w, &reports[i], i > 0); err != nil {
				return err
			}
		}
		return nil
	case "wide":
		return writeWatchTable(w, reports, true)
	case "table", "":
		return writeWatchTable(w, reports, false)
	default:
		return fmt.Errorf("unknown output format: %s (supported: table, wide, json, yaml)", outputFormat)
	}
}

func writeWatchEvent(w io.Writer, report *securityv1alpha1.TLSComplianceReport, deleted bool) error {
	switch outputFormat {
	case "json":
		return writeWatchJSON(w, report)
	case "yaml":
		return writeWatchYAML(w, report, true)
	case "wide":
		_, err := fmt.Fprintln(w, formatReportTableRow(report, true, deleted))
		return err
	case "table", "":
		_, err := fmt.Fprintln(w, formatReportTableRow(report, false, deleted))
		return err
	default:
		return fmt.Errorf("unknown output format: %s (supported: table, wide, json, yaml)", outputFormat)
	}
}

func writeWatchJSON(w io.Writer, report *securityv1alpha1.TLSComplianceReport) error {
	enc := json.NewEncoder(w)
	return enc.Encode(export.ToJSONReports([]securityv1alpha1.TLSComplianceReport{*report})[0])
}

func writeWatchYAML(w io.Writer, report *securityv1alpha1.TLSComplianceReport, separator bool) error {
	if separator {
		if _, err := fmt.Fprintln(w, "---"); err != nil {
			return err
		}
	}
	data, err := sigsyaml.Marshal(export.ToJSONReports([]securityv1alpha1.TLSComplianceReport{*report})[0])
	if err != nil {
		return fmt.Errorf("marshalling watch YAML: %w", err)
	}
	_, err = w.Write(data)
	return err
}

func writeWatchTable(w io.Writer, reports []securityv1alpha1.TLSComplianceReport, wide bool) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if wide {
		_, _ = fmt.Fprintln(tw, reportTableWideHeader)
	} else {
		_, _ = fmt.Fprintln(tw, reportTableHeader)
	}
	for i := range reports {
		_, _ = fmt.Fprintln(tw, formatReportTableRow(&reports[i], wide, false))
	}
	return tw.Flush()
}

const reportTableHeader = "NAME\tHOST\tPORT\tSOURCE\tCOMPLIANCE\tGRADE\tFS\tTLS 1.3\tTLS 1.2\tPQC\tMLKEM"
const reportTableWideHeader = "NAME\tHOST\tPORT\tSOURCE\tNAMESPACE\tCOMPLIANCE\tGRADE\tFS\tTLS 1.3\tTLS 1.2\tTLS 1.0\tSSL 3.0\tPQC\tMLKEM\tISSUER\tCERT EXPIRY"

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
	_, _ = fmt.Fprintln(w, reportTableHeader)
	for i := range reports {
		_, _ = fmt.Fprintln(w, formatReportTableRow(&reports[i], false, false))
	}
	return w.Flush()
}

func printReportTableWide(reports []securityv1alpha1.TLSComplianceReport) error {
	if len(reports) == 0 {
		return printNoResourcesFound()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, reportTableWideHeader)
	for i := range reports {
		_, _ = fmt.Fprintln(w, formatReportTableRow(&reports[i], true, false))
	}
	return w.Flush()
}

func formatReportTableRow(r *securityv1alpha1.TLSComplianceReport, wide, deleted bool) string {
	compliance := string(r.Status.ComplianceStatus)
	if deleted {
		compliance = "Deleted"
	}
	if !wide {
		return fmt.Sprintf("%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
			r.Name,
			r.Spec.Host,
			r.Spec.Port,
			string(r.Spec.SourceKind),
			compliance,
			r.Status.OverallCipherGrade,
			boolDash(r.Status.ForwardSecrecy),
			boolDash(r.Status.TLSVersions.TLS13),
			boolDash(r.Status.TLSVersions.TLS12),
			string(r.Status.PQCReadiness),
			boolDash(r.Status.MLKEMSupported),
		)
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
	return fmt.Sprintf("%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
		r.Name,
		r.Spec.Host,
		r.Spec.Port,
		string(r.Spec.SourceKind),
		r.Spec.SourceNamespace,
		compliance,
		r.Status.OverallCipherGrade,
		boolDash(r.Status.ForwardSecrecy),
		boolDash(r.Status.TLSVersions.TLS13),
		boolDash(r.Status.TLSVersions.TLS12),
		boolDash(r.Status.TLSVersions.TLS10),
		boolDash(r.Status.TLSVersions.SSL30),
		string(r.Status.PQCReadiness),
		boolDash(r.Status.MLKEMSupported),
		issuer,
		expiry,
	)
}

func boolDash(b bool) string {
	if b {
		return "true"
	}
	return "-"
}

func reportListOptions(resourceVersion string) ([]client.ListOption, error) {
	var opts []client.ListOption
	if labelSelector != "" {
		sel, err := labels.Parse(labelSelector)
		if err != nil {
			return nil, fmt.Errorf("parsing label selector: %w", err)
		}
		opts = append(opts, client.MatchingLabelsSelector{Selector: sel})
	}
	if resourceVersion != "" {
		opts = append(opts, &client.ListOptions{
			Raw: &metav1.ListOptions{ResourceVersion: resourceVersion},
		})
	}
	return opts, nil
}
