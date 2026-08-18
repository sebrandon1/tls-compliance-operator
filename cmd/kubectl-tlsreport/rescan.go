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
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

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
	report.Annotations[securityv1alpha1.RescanAnnotation] = time.Now().UTC().Format(time.RFC3339)
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
			if _, hasAnnotation := updated.Annotations[securityv1alpha1.RescanAnnotation]; !hasAnnotation {
				fmt.Fprintf(os.Stderr, "Rescan complete for %s (status: %s)\n", name, updated.Status.ComplianceStatus)
				return nil
			}
		}
	}
}
