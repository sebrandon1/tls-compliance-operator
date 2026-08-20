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
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func newTargetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage TLSComplianceTarget resources",
	}
	cmd.AddCommand(newTargetListCmd())
	cmd.AddCommand(newTargetGetCmd())
	cmd.AddCommand(newTargetDescribeCmd())
	cmd.AddCommand(newTargetCreateCmd())
	cmd.AddCommand(newTargetUpdateCmd())
	cmd.AddCommand(newTargetDeleteCmd())
	return cmd
}

func newTargetListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all TLSComplianceTargets",
		Example: `  # List targets in table format
  kubectl tlsreport target list

  # List non-compliant targets
  kubectl tlsreport target list --status NonCompliant

  # Sort by host
  kubectl tlsreport target list --sort-by host

  # Filter by label selector
  kubectl tlsreport target list -l team=platform

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

func newTargetUpdateCmd() *cobra.Command {
	var host string
	var port int

	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update host and/or port on an existing TLSComplianceTarget",
		Example: `  # Update the host
  kubectl tlsreport target update google-com-443 --host google.com

  # Update the port
  kubectl tlsreport target update google-com-443 --port 8443

  # Update host and port
  kubectl tlsreport target update google-com-443 --host google.com --port 443`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostSet := cmd.Flags().Changed("host")
			portSet := cmd.Flags().Changed("port")
			return runTargetUpdate(cmd.Context(), args[0], host, port, hostSet, portSet)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "New hostname or IP")
	cmd.Flags().IntVar(&port, "port", 0, "New port (1-65535)")
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
	targets = filterTargetsByStatus(targets, filterOpts.Status)
	if err := sortTargets(targets, sortBy); err != nil {
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

func runTargetUpdate(ctx context.Context, name, host string, port int, hostSet, portSet bool) error {
	if err := validateTargetUpdate(host, port, hostSet, portSet); err != nil {
		return err
	}

	c, err := buildClient()
	if err != nil {
		return err
	}
	return updateTarget(ctx, c, name, host, port, hostSet, portSet)
}

func validateTargetUpdate(host string, port int, hostSet, portSet bool) error {
	if !hostSet && !portSet {
		return fmt.Errorf("at least one of --host or --port is required")
	}
	if hostSet && strings.TrimSpace(host) == "" {
		return fmt.Errorf("host must not be empty")
	}
	if portSet && (port < 1 || port > 65535) {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
	return nil
}

func updateTarget(ctx context.Context, c client.Client, name, host string, port int, hostSet, portSet bool) error {
	var target securityv1alpha1.TLSComplianceTarget
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &target); err != nil {
		return fmt.Errorf("getting TLSComplianceTarget %q: %w", name, err)
	}

	if hostSet {
		target.Spec.Host = host
	}
	if portSet {
		target.Spec.Port = int32(port)
	}

	if err := c.Update(ctx, &target); err != nil {
		return fmt.Errorf("updating target %q: %w", name, err)
	}

	fmt.Fprintf(os.Stderr, "tlscompliancetarget/%s updated\n", name)
	return nil
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
	return fetchTargetsWithClient(ctx, c)
}

func fetchTargetsWithClient(ctx context.Context, c client.Client) ([]securityv1alpha1.TLSComplianceTarget, error) {
	listOpts := []client.ListOption{}
	if labelSelector != "" {
		sel, err := labels.Parse(labelSelector)
		if err != nil {
			return nil, fmt.Errorf("parsing label selector: %w", err)
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: sel})
	}

	var targetList securityv1alpha1.TLSComplianceTargetList
	if err := c.List(ctx, &targetList, listOpts...); err != nil {
		return nil, fmt.Errorf("listing TLSComplianceTargets: %w", err)
	}
	return targetList.Items, nil
}

func filterTargetsByStatus(targets []securityv1alpha1.TLSComplianceTarget, status string) []securityv1alpha1.TLSComplianceTarget {
	if status == "" {
		return targets
	}
	out := make([]securityv1alpha1.TLSComplianceTarget, 0, len(targets))
	for i := range targets {
		if strings.EqualFold(string(targets[i].Status.ComplianceStatus), status) {
			out = append(out, targets[i])
		}
	}
	return out
}

func sortTargets(targets []securityv1alpha1.TLSComplianceTarget, key string) error {
	switch strings.ToLower(key) {
	case "":
		return nil
	case "host":
		sort.SliceStable(targets, func(i, j int) bool {
			return targets[i].Spec.Host < targets[j].Spec.Host
		})
	case "port":
		sort.SliceStable(targets, func(i, j int) bool {
			return targets[i].Spec.Port < targets[j].Spec.Port
		})
	case "compliance", "status":
		sort.SliceStable(targets, func(i, j int) bool {
			return string(targets[i].Status.ComplianceStatus) < string(targets[j].Status.ComplianceStatus)
		})
	case "expiry", "grade", "pqc":
		return fmt.Errorf("unsupported --sort-by %q for targets (supported: host, port, compliance)", key)
	default:
		return fmt.Errorf("unknown --sort-by %q (supported: host, port, compliance)", key)
	}
	return nil
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
