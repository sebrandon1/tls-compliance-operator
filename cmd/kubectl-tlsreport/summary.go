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
	"os"

	"github.com/spf13/cobra"

	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
)

func newSummaryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "summary",
		Short: "Show a compliance summary of all TLS endpoints",
		Example: `  # Show summary of all endpoints
  kubectl tlsreport summary

  # Show summary for a specific namespace
  kubectl tlsreport summary -n production`,
		RunE: runSummary,
	}
}

func runSummary(cmd *cobra.Command, _ []string) error {
	reports, err := fetchReports(cmd.Context())
	if err != nil {
		return err
	}

	reports, err = export.FilterReports(reports, &filterOpts)
	if err != nil {
		return err
	}

	if len(reports) == 0 {
		return printNoResourcesFound()
	}

	export.SortReports(reports, sortBy)

	if err := export.WriteSummary(os.Stdout, reports); err != nil {
		return err
	}
	return checkExitCode(reports)
}
