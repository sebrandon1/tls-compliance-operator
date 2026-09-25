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
	"io"
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
				return runRescanAll(cmd.Context(), waitFlag, timeout, cmd.ErrOrStderr())
			}
			return runRescan(cmd.Context(), args[0], waitFlag, timeout, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&allFlag, "all", false, "Rescan all reports matching current filters")
	cmd.Flags().BoolVar(&waitFlag, "wait", false, "Wait for the rescan to complete")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "Timeout when waiting for rescan completion")
	return cmd
}

func runRescan(ctx context.Context, name string, wait bool, timeout time.Duration, writers ...io.Writer) error {
	c, err := clientBuilder()
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

	errOut := writerOrDefault(writers, 0, os.Stderr)
	if _, err := fmt.Fprintf(errOut, "Rescan triggered for %s\n", name); err != nil {
		return err
	}

	if !wait {
		return nil
	}

	return waitForRescan(ctx, c, name, timeout, errOut)
}

func runRescanAll(ctx context.Context, wait bool, timeout time.Duration, writers ...io.Writer) error {
	c, err := clientBuilder()
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

	return rescanReports(ctx, c, reports, wait, timeout, writers...)
}

func rescanReports(ctx context.Context, c client.Client, reports []securityv1alpha1.TLSComplianceReport, wait bool, timeout time.Duration, writers ...io.Writer) error {
	errOut := writerOrDefault(writers, 0, os.Stderr)
	if len(reports) == 0 {
		return printNoMatchingReports(errOut)
	}

	diagnostics := &outputWriter{w: errOut}
	var triggered []string
	var triggerFailed int
	for i := range reports {
		if err := triggerRescan(ctx, c, &reports[i]); err != nil {
			diagnostics.Fprintf("Failed to trigger rescan for %s: %v\n", reports[i].Name, err)
			triggerFailed++
			continue
		}
		triggered = append(triggered, reports[i].Name)
	}

	diagnostics.Fprintf("Rescan triggered for %d/%d reports\n", len(triggered), len(reports))

	if !wait || len(triggered) == 0 {
		if diagnostics.Err() != nil {
			return diagnostics.Err()
		}
		if triggerFailed > 0 {
			return exitCodeError{code: 1}
		}
		return nil
	}

	completed, err := waitForRescans(ctx, c, triggered, timeout, errOut)
	if err != nil {
		return err
	}
	diagnostics.Fprintf("Rescan completed for %d/%d reports\n", completed, len(triggered))
	if diagnostics.Err() != nil {
		return diagnostics.Err()
	}
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

func waitForRescan(ctx context.Context, c client.Client, name string, timeout time.Duration, writers ...io.Writer) error {
	errOut := writerOrDefault(writers, 0, os.Stderr)
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
				if _, err := fmt.Fprintf(errOut, "Rescan complete for %s (status: %s)\n", name, updated.Status.ComplianceStatus); err != nil {
					return err
				}
				return nil
			}
		}
	}
}

const rescanWaitPollInterval = 2 * time.Second

func waitForRescans(ctx context.Context, c client.Client, names []string, timeout time.Duration, writers ...io.Writer) (int, error) {
	errOut := writerOrDefault(writers, 0, os.Stderr)
	waitCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	pending := make(map[string]struct{}, len(names))
	for _, name := range names {
		pending[name] = struct{}{}
	}
	total := len(names)
	completed := 0

	printProgress := func() error {
		_, err := fmt.Fprintf(errOut, "\rscanned %d/%d", completed, total)
		return err
	}

	check := func() error {
		for name := range pending {
			var updated securityv1alpha1.TLSComplianceReport
			if err := c.Get(waitCtx, client.ObjectKey{Name: name}, &updated); err != nil {
				return fmt.Errorf("checking rescan status: %w", err)
			}
			if _, has := updated.Annotations[securityv1alpha1.RescanAnnotation]; !has {
				delete(pending, name)
				completed++
			}
		}
		return nil
	}

	if err := check(); err != nil {
		if _, writeErr := fmt.Fprintln(errOut); writeErr != nil {
			return completed, writeErr
		}
		if _, writeErr := fmt.Fprintf(errOut, "%v\n", err); writeErr != nil {
			return completed, writeErr
		}
		return completed, nil
	}
	if err := printProgress(); err != nil {
		return completed, err
	}

	ticker := time.NewTicker(rescanWaitPollInterval)
	defer ticker.Stop()

	for len(pending) > 0 {
		select {
		case <-waitCtx.Done():
			if _, err := fmt.Fprintln(errOut); err != nil {
				return completed, err
			}
			for name := range pending {
				if _, err := fmt.Fprintf(errOut, "Timeout waiting for %s\n", name); err != nil {
					return completed, err
				}
			}
			return completed, nil
		case <-ticker.C:
			if err := check(); err != nil {
				if _, writeErr := fmt.Fprintln(errOut); writeErr != nil {
					return completed, writeErr
				}
				if _, writeErr := fmt.Fprintf(errOut, "%v\n", err); writeErr != nil {
					return completed, writeErr
				}
				return completed, nil
			}
			if err := printProgress(); err != nil {
				return completed, err
			}
		}
	}

	if _, err := fmt.Fprintln(errOut); err != nil {
		return completed, err
	}
	return completed, nil
}
