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

	var writeErr error
	switch format {
	case "csv":
		writeErr = export.WriteCSV(os.Stdout, reports)
	case "json":
		if rawExport {
			writeErr = export.WriteRawJSON(os.Stdout, reports)
		} else {
			writeErr = export.WriteJSON(os.Stdout, reports)
		}
	case "yaml":
		if rawExport {
			writeErr = export.WriteRawYAML(os.Stdout, reports)
		} else {
			writeErr = export.WriteYAML(os.Stdout, reports)
		}
	case "junit":
		writeErr = export.WriteJUnit(os.Stdout, reports)
	case "markdown", "md":
		writeErr = export.WriteMarkdown(os.Stdout, reports)
	case "html":
		writeErr = export.WriteHTML(os.Stdout, reports)
	case "sarif":
		writeErr = export.WriteSARIF(os.Stdout, reports)
	}
	if writeErr != nil {
		return writeErr
	}

	return checkExitCode(reports)
}
