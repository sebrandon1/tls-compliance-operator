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
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func runExport(cmd *cobra.Command, args []string) error {
	format := "csv"
	if len(args) > 0 {
		format = args[0]
	}

	switch format {
	case "csv", "json", "yaml", "junit", "markdown", "md", "html", "sarif":
	default:
		return fmt.Errorf("unknown format: %s (supported: csv, json, yaml, junit, markdown, md, html, sarif)", format)
	}

	if rawExport && format != "json" && format != "yaml" {
		return fmt.Errorf("--raw is only supported with json and yaml formats")
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

	// Keep stdout machine-readable: the group assertion goes to stderr.
	if err := writeGroupsGate(cmd.ErrOrStderr(), reports); err != nil {
		return err
	}

	return writeFilteredReports(format, reports, cmd.OutOrStdout(), cmd.ErrOrStderr())
}

func writeFilteredReports(format string, reports []securityv1alpha1.TLSComplianceReport, writers ...io.Writer) error {
	if len(reports) == 0 {
		if err := printNoMatchingReports(writerOrDefault(writers, 1, os.Stderr)); err != nil {
			return err
		}
	}

	out := writerOrDefault(writers, 0, os.Stdout)
	var writeErr error
	switch format {
	case "csv":
		writeErr = export.WriteCSV(out, reports)
	case "json":
		if rawExport {
			writeErr = export.WriteRawJSON(out, reports)
		} else {
			writeErr = export.WriteJSON(out, reports)
		}
	case "yaml":
		if rawExport {
			writeErr = export.WriteRawYAML(out, reports)
		} else {
			writeErr = export.WriteYAML(out, reports)
		}
	case "junit":
		opts, err := junitOptions()
		if err != nil {
			return err
		}
		writeErr = export.WriteJUnitWithOptions(out, reports, opts)
	case "markdown", "md":
		writeErr = export.WriteMarkdown(out, reports)
	case "html":
		writeErr = export.WriteHTML(out, reports)
	case "sarif":
		writeErr = export.WriteSARIF(out, reports)
	}
	if writeErr != nil {
		return writeErr
	}

	return checkExitCode(reports)
}

// junitOptions carries the configured gates into the JUnit report, so a gate
// failure shows up as a testcase failure instead of only an exit code.
func junitOptions() (export.JUnitOptions, error) {
	opts := export.JUnitOptions{RequirePQC: requirePQC}
	if strings.TrimSpace(expectedGroups) == "" {
		return opts, nil
	}

	groups := export.SplitGroups(expectedGroups)
	if len(groups) == 0 {
		return export.JUnitOptions{}, fmt.Errorf("--expected-groups contains no group names")
	}
	mode, err := export.ParseGroupsMode(groupsMode)
	if err != nil {
		return export.JUnitOptions{}, err
	}

	opts.ExpectedGroups = groups
	opts.GroupsMode = mode
	return opts, nil
}

// evaluateGroupsGate parses the group flags and evaluates them against reports.
func evaluateGroupsGate(reports []securityv1alpha1.TLSComplianceReport) (export.GroupsGateResult, error) {
	groups, err := parseExpectedGroups()
	if err != nil {
		return export.GroupsGateResult{}, err
	}
	mode, err := export.ParseGroupsMode(groupsMode)
	if err != nil {
		return export.GroupsGateResult{}, err
	}
	return export.EvaluateExpectedGroups(reports, groups, mode), nil
}

// writeGroupsGate prints the --expected-groups assertion when one is configured.
func writeGroupsGate(w io.Writer, reports []securityv1alpha1.TLSComplianceReport) error {
	if strings.TrimSpace(expectedGroups) == "" {
		return nil
	}
	result, err := evaluateGroupsGate(reports)
	if err != nil {
		return err
	}
	return export.WriteGroupsGate(w, &result)
}
