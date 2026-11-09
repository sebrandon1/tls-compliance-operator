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
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

func newTargetImportCmd() *cobra.Command {
	var fromFile string
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Create TLSComplianceTargets from a YAML export or a host:port list",
		Example: `  # Import targets exported from another cluster
  kubectl tlsreport target export --file targets.yaml
  kubectl tlsreport target import --from-file targets.yaml

  # Import a plain host:port list
  kubectl tlsreport target import --from-file endpoints.txt`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTargetImport(cmd, fromFile, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&fromFile, "from-file", "", "File containing a YAML export or one host[:port] per line")
	_ = cmd.MarkFlagRequired("from-file")
	return cmd
}

func newTargetExportCmd() *cobra.Command {
	var outputFile string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all TLSComplianceTargets as YAML that target import accepts",
		Example: `  # Print targets as YAML
  kubectl tlsreport target export

  # Write them to a file
  kubectl tlsreport target export --file targets.yaml`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTargetExport(cmd, outputFile, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&outputFile, "file", "", "Write the export to this file instead of stdout")
	return cmd
}

// importTarget is one host/port pair to create.
type importTarget struct {
	Host string
	Port int32
}

func runTargetImport(cmd *cobra.Command, fromFile string, out io.Writer) error {
	data, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", fromFile, err)
	}
	targets, err := parseImportData(data)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets found in %s", fromFile)
	}

	c, err := clientBuilder()
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	created, skipped := 0, 0
	for _, t := range targets {
		target := &securityv1alpha1.TLSComplianceTarget{
			ObjectMeta: metav1.ObjectMeta{Name: targetName(t.Host, t.Port)},
			Spec: securityv1alpha1.TLSComplianceTargetSpec{
				Host: t.Host,
				Port: int32Pointer(t.Port),
			},
		}
		if err := c.Create(ctx, target); err != nil {
			if apierrors.IsAlreadyExists(err) {
				skipped++
				continue
			}
			return fmt.Errorf("creating target %s: %w", target.Name, err)
		}
		created++
	}

	_, err = fmt.Fprintf(out, "created %d target(s), skipped %d existing\n", created, skipped)
	return err
}

func runTargetExport(cmd *cobra.Command, outputFile string, out io.Writer) error {
	c, err := clientBuilder()
	if err != nil {
		return err
	}

	var list securityv1alpha1.TLSComplianceTargetList
	if err := c.List(cmd.Context(), &list); err != nil {
		return fmt.Errorf("listing targets: %w", err)
	}

	exported := securityv1alpha1.TLSComplianceTargetList{
		TypeMeta: metav1.TypeMeta{APIVersion: securityv1alpha1.GroupVersion.String(), Kind: "TLSComplianceTargetList"},
	}
	for i := range list.Items {
		item := list.Items[i]
		clean := securityv1alpha1.TLSComplianceTarget{
			TypeMeta: metav1.TypeMeta{APIVersion: securityv1alpha1.GroupVersion.String(), Kind: "TLSComplianceTarget"},
			ObjectMeta: metav1.ObjectMeta{
				Name:   item.Name,
				Labels: item.Labels,
			},
			Spec: item.Spec,
		}
		exported.Items = append(exported.Items, clean)
	}

	data, err := sigsyaml.Marshal(exported)
	if err != nil {
		return fmt.Errorf("marshalling targets: %w", err)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", outputFile, err)
		}
		_, err = fmt.Fprintf(out, "exported %d target(s) to %s\n", len(exported.Items), outputFile)
		return err
	}
	_, err = out.Write(data)
	return err
}

// parseImportData accepts a TLSComplianceTargetList, a single
// TLSComplianceTarget, or a plain host[:port] list.
func parseImportData(data []byte) ([]importTarget, error) {
	var list securityv1alpha1.TLSComplianceTargetList
	if err := sigsyaml.Unmarshal(data, &list); err == nil && len(list.Items) > 0 {
		return importTargetsFromList(list.Items), nil
	}

	var single securityv1alpha1.TLSComplianceTarget
	if err := sigsyaml.Unmarshal(data, &single); err == nil && single.Spec.Host != "" {
		return importTargetsFromList([]securityv1alpha1.TLSComplianceTarget{single}), nil
	}

	return parseHostPortLines(string(data))
}

// importTargetsFromList converts CR specs to host/port pairs, applying the
// default port when unset.
func importTargetsFromList(items []securityv1alpha1.TLSComplianceTarget) []importTarget {
	targets := make([]importTarget, 0, len(items))
	for i := range items {
		host := strings.TrimSpace(items[i].Spec.Host)
		if host == "" {
			continue
		}
		targets = append(targets, importTarget{Host: host, Port: items[i].Spec.EffectivePort()})
	}
	return targets
}

// parseHostPortLines parses one host[:port] per line, skipping blanks and
// comments.
func parseHostPortLines(data string) ([]importTarget, error) {
	var targets []importTarget
	for lineNo, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, port := splitHostPort(line)
		if host == "" {
			return nil, fmt.Errorf("line %d: invalid host %q", lineNo+1, line)
		}
		targets = append(targets, importTarget{Host: host, Port: port})
	}
	return targets, nil
}

// splitHostPort splits host[:port], defaulting to 443. IPv6 literals must be
// bracketed, as in [2001:db8::1]:8443.
func splitHostPort(line string) (string, int32) {
	if strings.HasPrefix(line, "[") {
		host, rest, found := strings.Cut(line, "]")
		if !found {
			return "", 0
		}
		host = strings.TrimPrefix(host, "[")
		if rest == "" {
			return host, defaultTargetPort
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0
		}
		port, ok := parseImportPort(rest[1:])
		if !ok {
			return "", 0
		}
		return host, port
	}

	host, portStr, found := strings.Cut(line, ":")
	if !found {
		return line, defaultTargetPort
	}
	port, ok := parseImportPort(portStr)
	if !ok {
		return "", 0
	}
	return host, port
}

// parseImportPort parses and bounds-checks a port.
func parseImportPort(value string) (int32, bool) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return int32(port), true
}

// defaultTargetPort matches the CRD and webhook default.
const defaultTargetPort int32 = 443

// targetName builds the deterministic CR name for a host and port.
func targetName(host string, port int32) string {
	sanitized := strings.ToLower(host)
	sanitized = strings.NewReplacer(".", "-", ":", "-").Replace(sanitized)
	return fmt.Sprintf("%s-%d", sanitized, port)
}
