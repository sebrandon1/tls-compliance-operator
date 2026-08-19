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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func newDiffCmd() *cobra.Command {
	var failOnRegression bool
	var diffOutput string

	cmd := &cobra.Command{
		Use:   "diff <before-file> [after-file]",
		Short: "Compare two TLS compliance snapshots",
		Long: `Compare two JSON/YAML snapshots (or a snapshot against the live cluster).

Endpoints are matched by host:port. The output lists added and removed
endpoints plus changes in compliance, cipher grade, TLS versions, PQC
readiness, and certificates.

With one file argument, the file is the "before" snapshot and live cluster
reports are the "after" snapshot. Filter flags apply only to the live fetch.`,
		Example: `  # Capture a baseline, then compare against the live cluster
  kubectl tlsreport json > before.json
  kubectl tlsreport diff before.json

  # Compare two exported snapshots (for example, before and after an upgrade)
  kubectl tlsreport diff before.json after.json

  # Fail CI when compliance, grade, or TLS posture gets worse
  kubectl tlsreport diff before.json after.json --fail-on-regression

  # Machine-readable output
  kubectl tlsreport diff before.json after.json -o json`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd, args, failOnRegression, diffOutput)
		},
	}
	cmd.Flags().BoolVar(&failOnRegression, "fail-on-regression", false,
		"Exit with code 1 if any endpoint regressed (worse compliance, grade, legacy TLS, lost TLS 1.3, or worse PQC)")
	cmd.Flags().StringVarP(&diffOutput, "output", "o", "text", "Output format: text, json")
	_ = cmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"text", "json"}, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func runDiff(cmd *cobra.Command, args []string, failOnRegression bool, output string) error {
	before, err := loadSnapshotFile(args[0])
	if err != nil {
		return err
	}

	var after []export.JSONReport
	if len(args) == 2 {
		if !filterOpts.IsEmpty() {
			return fmt.Errorf("filter flags apply only when comparing a snapshot to the live cluster")
		}
		after, err = loadSnapshotFile(args[1])
		if err != nil {
			return err
		}
	} else {
		reports, err := fetchReports(cmd.Context())
		if err != nil {
			return err
		}
		reports, err = export.FilterReports(reports, &filterOpts)
		if err != nil {
			return err
		}
		after = export.ToJSONReports(reports)
	}

	diff := export.DiffSnapshots(before, after)

	switch output {
	case "", "text":
		if err := export.WriteDiff(os.Stdout, &diff); err != nil {
			return err
		}
	case "json":
		if err := export.WriteDiffJSON(os.Stdout, &diff); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown output format: %s (supported: text, json)", output)
	}

	if failOnRegression && diff.HasRegressions() {
		return exitCodeError{code: 1}
	}
	return nil
}

func loadSnapshotFile(path string) ([]export.JSONReport, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: snapshot path is a user-supplied CLI argument
	if err != nil {
		return nil, fmt.Errorf("reading snapshot %q: %w", path, err)
	}
	reports, err := export.LoadSnapshot(data)
	if err != nil {
		return nil, fmt.Errorf("parsing snapshot %q: %w", path, err)
	}
	return reports, nil
}
