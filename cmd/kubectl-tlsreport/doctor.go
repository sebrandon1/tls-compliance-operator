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
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

const defaultOperatorNamespace = "tls-compliance-operator-system"

// Doctor check statuses.
const (
	doctorPass = "PASS"
	doctorWarn = "WARN"
	doctorFail = "FAIL"
)

// doctorCheck is one diagnostic result.
type doctorCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// doctorClients bundles the read-only clients the checks need.
type doctorClients struct {
	discovery discovery.DiscoveryInterface
	kube      kubernetes.Interface
	reader    client.Reader
}

func newDoctorCmd() *cobra.Command {
	var operatorNamespace, output string
	var failOnError bool
	var scanInterval time.Duration

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose why TLS compliance data is missing or stale",
		Long: `Run read-only checks against the cluster and print PASS/WARN/FAIL for each.

Checks cover API reachability, the CRDs, RBAC for listing reports, operator
health, scan freshness, and the optional admission webhook. Nothing is created,
updated, or deleted.`,
		Example: `  # Diagnose an empty report list
  kubectl tlsreport doctor

  # Machine-readable output, never exit non-zero
  kubectl tlsreport doctor -o json --fail-on-error=false`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clients, err := buildDoctorClients()
			if err != nil {
				return err
			}
			return runDoctor(cmd.Context(), cmd.OutOrStdout(), clients, doctorOptions{
				operatorNamespace: operatorNamespace,
				scanInterval:      scanInterval,
				output:            output,
				failOnError:       failOnError,
			})
		},
	}

	cmd.Flags().StringVar(&operatorNamespace, "operator-namespace", defaultOperatorNamespace,
		"Namespace the operator is installed in")
	cmd.Flags().BoolVar(&failOnError, "fail-on-error", true, "Exit with code 1 when any check reports FAIL")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "Output format: table or json")
	cmd.Flags().DurationVar(&scanInterval, "scan-interval", time.Hour,
		"Configured scan interval, used to judge report freshness")
	return cmd
}

type doctorOptions struct {
	operatorNamespace string
	scanInterval      time.Duration
	output            string
	failOnError       bool
}

func runDoctor(ctx context.Context, out io.Writer, clients doctorClients, opts doctorOptions) error {
	switch opts.output {
	case "table", "json":
	default:
		return fmt.Errorf("unknown output format: %s (supported: table, json)", opts.output)
	}

	checks := []doctorCheck{
		checkAPIServer(clients),
		checkCRDs(clients),
		checkRBAC(ctx, clients),
		checkOperatorHealth(ctx, clients, opts.operatorNamespace),
		checkScanFreshness(ctx, clients, opts.scanInterval),
		checkWebhook(ctx, clients, opts.operatorNamespace),
	}

	if opts.output == "json" {
		if err := writeDoctorJSON(out, checks); err != nil {
			return err
		}
	} else if err := writeDoctorTable(out, checks); err != nil {
		return err
	}

	if opts.failOnError {
		for _, c := range checks {
			if c.Status == doctorFail {
				return fmt.Errorf("%d check(s) failed", countByStatus(checks, doctorFail))
			}
		}
	}
	return nil
}

func countByStatus(checks []doctorCheck, status string) int {
	n := 0
	for _, c := range checks {
		if c.Status == status {
			n++
		}
	}
	return n
}

func writeDoctorTable(out io.Writer, checks []doctorCheck) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL\tREMEDIATION"); err != nil {
		return err
	}
	for _, c := range checks {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.Status, c.Name, c.Message, c.Remediation); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeDoctorJSON(out io.Writer, checks []doctorCheck) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sortedChecks(checks)); err != nil {
		return fmt.Errorf("encoding doctor results: %w", err)
	}
	return nil
}

// checkAPIServer verifies the API server answers at all.
func checkAPIServer(clients doctorClients) doctorCheck {
	check := doctorCheck{Name: "api-server"}
	if clients.discovery == nil {
		check.Status = doctorFail
		check.Message = "no discovery client"
		return check
	}
	version, err := clients.discovery.ServerVersion()
	if err != nil {
		check.Status = doctorFail
		check.Message = "cannot reach the API server: " + err.Error()
		check.Remediation = "check --kubeconfig/--context and network access to the API server"
		return check
	}
	check.Status = doctorPass
	check.Message = "reachable (server " + version.GitVersion + ")"
	return check
}

// crdResources are the resources the operator owns.
var crdResources = []string{"tlscompliancereports", "tlscompliancetargets"}

// checkCRDs verifies the CRDs are installed and served.
func checkCRDs(clients doctorClients) doctorCheck {
	check := doctorCheck{Name: "crds"}
	if clients.discovery == nil {
		check.Status = doctorFail
		check.Message = "no discovery client"
		return check
	}
	groupVersion := securityv1alpha1.GroupVersion.String()
	resources, err := clients.discovery.ServerResourcesForGroupVersion(groupVersion)
	if err != nil {
		check.Status = doctorFail
		check.Message = fmt.Sprintf("API group %s is not served: %v", groupVersion, err)
		check.Remediation = "install the CRDs (kubectl apply -f dist/install.yaml or the OLM bundle)"
		return check
	}
	served := make(map[string]bool, len(resources.APIResources))
	for i := range resources.APIResources {
		served[resources.APIResources[i].Name] = true
	}
	var missing []string
	for _, r := range crdResources {
		if !served[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		check.Status = doctorFail
		check.Message = "missing resources: " + strings.Join(missing, ", ")
		check.Remediation = "install or upgrade the CRDs for this operator version"
		return check
	}
	check.Status = doctorPass
	check.Message = "both CRDs are served"
	return check
}

// checkRBAC verifies the caller may list and get reports and targets.
func checkRBAC(ctx context.Context, clients doctorClients) doctorCheck {
	check := doctorCheck{Name: "rbac"}
	if clients.kube == nil {
		check.Status = doctorWarn
		check.Message = "cannot evaluate permissions without a Kubernetes client"
		return check
	}
	var denied []string
	for _, verb := range []string{"list", "get"} {
		for _, resource := range crdResources {
			review := &authorizationv1.SelfSubjectAccessReview{
				Spec: authorizationv1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Group:    securityv1alpha1.GroupVersion.Group,
						Version:  securityv1alpha1.GroupVersion.Version,
						Resource: resource,
						Verb:     verb,
					},
				},
			}
			resp, err := clients.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
			if err != nil {
				check.Status = doctorWarn
				check.Message = "cannot evaluate permissions: " + err.Error()
				check.Remediation = "grant access to create selfsubjectaccessreviews, or review RBAC manually"
				return check
			}
			if !resp.Status.Allowed {
				denied = append(denied, verb+" "+resource)
			}
		}
	}
	if len(denied) > 0 {
		check.Status = doctorWarn
		check.Message = "not allowed: " + strings.Join(denied, ", ")
		check.Remediation = "bind a ClusterRole granting list/get on tlscompliancereports.security.telco.openshift.io and tlscompliancetargets.security.telco.openshift.io"
		return check
	}
	check.Status = doctorPass
	check.Message = "list and get are allowed on both CRDs"
	return check
}

// checkOperatorHealth reports ready replicas and leader election for the
// manager Deployment.
func checkOperatorHealth(ctx context.Context, clients doctorClients, namespace string) doctorCheck {
	check := doctorCheck{Name: "operator"}
	if clients.kube == nil {
		check.Status = doctorWarn
		check.Message = "cannot inspect the operator Deployment without a Kubernetes client"
		return check
	}
	selector := labels.SelectorFromSet(labels.Set{"control-plane": "controller-manager"}).String()
	deployments, err := clients.kube.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		check.Status = doctorFail
		check.Message = fmt.Sprintf("cannot list Deployments in %s: %v", namespace, err)
		check.Remediation = "pass --operator-namespace if the operator runs elsewhere"
		return check
	}
	if len(deployments.Items) == 0 {
		check.Status = doctorFail
		check.Message = "no operator Deployment in namespace " + namespace
		check.Remediation = "install the operator or pass --operator-namespace"
		return check
	}
	deployment := &deployments.Items[0]
	ready := deployment.Status.ReadyReplicas
	leaderElection := leaderElectionState(deployment)
	desired := int32(0)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	if ready == 0 {
		check.Status = doctorFail
		check.Message = fmt.Sprintf("Deployment %s has no ready replicas (leader election: %s)", deployment.Name, leaderElection)
		check.Remediation = "inspect the manager pod logs and events in " + namespace
		return check
	}
	check.Status = doctorPass
	check.Message = fmt.Sprintf("%s ready, %d/%d replicas, leader election: %s",
		deployment.Name, ready, desired, leaderElection)
	return check
}

// leaderElectionState reports whether the manager is started with
// --leader-elect=true, based on the container args.
func leaderElectionState(deployment *appsv1.Deployment) string {
	for i := range deployment.Spec.Template.Spec.Containers {
		for _, arg := range deployment.Spec.Template.Spec.Containers[i].Args {
			if arg == "--leader-elect" {
				return "enabled"
			}
			if strings.HasPrefix(arg, "--leader-elect=") {
				if strings.TrimPrefix(arg, "--leader-elect=") == "true" {
					return "enabled"
				}
				return "disabled"
			}
		}
	}
	return "not configured"
}

// checkScanFreshness reports whether the newest report is older than two scan
// intervals, or whether reports are stuck Pending.
func checkScanFreshness(ctx context.Context, clients doctorClients, scanInterval time.Duration) doctorCheck {
	check := doctorCheck{Name: "scan-freshness"}
	if clients.reader == nil {
		check.Status = doctorWarn
		check.Message = "cannot read reports"
		return check
	}
	var list securityv1alpha1.TLSComplianceReportList
	if err := clients.reader.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		check.Status = doctorFail
		check.Message = "cannot list TLSComplianceReports: " + err.Error()
		check.Remediation = "check RBAC; run `kubectl tlsreport doctor` again after fixing permissions"
		return check
	}
	if len(list.Items) == 0 {
		check.Status = doctorWarn
		check.Message = "no reports exist"
		check.Remediation = "confirm endpoints exist in scanned namespaces; check the manager logs"
		return check
	}

	var newest time.Time
	pending := 0
	for i := range list.Items {
		r := &list.Items[i]
		if r.Status.LastCheckAt != nil && r.Status.LastCheckAt.After(newest) {
			newest = r.Status.LastCheckAt.Time
		}
		if r.Status.ComplianceStatus == securityv1alpha1.ComplianceStatusPending {
			pending++
		}
	}

	if newest.IsZero() {
		check.Status = doctorWarn
		check.Message = fmt.Sprintf("%d reports, none has completed a check", len(list.Items))
		check.Remediation = "the operator may not be scanning; check its logs"
		return check
	}
	age := time.Since(newest)
	if age > 2*scanInterval {
		check.Status = doctorWarn
		check.Message = fmt.Sprintf("newest check is %s old (scan interval %s)", age.Round(time.Minute), scanInterval)
		check.Remediation = "verify the operator is running and not outside a configured scan window"
		return check
	}
	check.Status = doctorPass
	check.Message = fmt.Sprintf("%d reports, newest check %s ago", len(list.Items), age.Round(time.Minute))
	if pending > 0 {
		check.Status = doctorWarn
		check.Message += fmt.Sprintf("; %d report(s) Pending", pending)
		check.Remediation = "Pending reports usually mean the manager cannot reach the endpoint; check logs"
	}
	return check
}

// checkWebhook reports whether the optional validating webhook is installed and
// has ready endpoints.
func checkWebhook(ctx context.Context, clients doctorClients, namespace string) doctorCheck {
	check := doctorCheck{Name: "webhook"}
	if clients.kube == nil {
		check.Status = doctorWarn
		check.Message = "cannot inspect webhook configuration"
		return check
	}
	configs, err := clients.kube.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		check.Status = doctorWarn
		check.Message = "cannot list ValidatingWebhookConfigurations: " + err.Error()
		return check
	}
	found := ""
	for i := range configs.Items {
		for j := range configs.Items[i].Webhooks {
			wh := &configs.Items[i].Webhooks[j]
			if wh.ClientConfig.Service != nil &&
				strings.HasPrefix(wh.Name, "vtlscompliancetarget") {
				found = wh.ClientConfig.Service.Name
			}
		}
	}
	if found == "" {
		check.Status = doctorWarn
		check.Message = "validation webhook is not installed"
		check.Remediation = "optional; TLSComplianceTargets are accepted without validation"
		return check
	}
	svc, err := clients.kube.CoreV1().Services(namespace).Get(ctx, found, metav1.GetOptions{})
	if err != nil {
		check.Status = doctorWarn
		check.Message = fmt.Sprintf("webhook Service %s/%s is missing: %v", namespace, found, err)
		check.Remediation = "pass --operator-namespace if the webhook runs elsewhere"
		return check
	}
	endpoints, err := clients.kube.CoreV1().Endpoints(namespace).Get(ctx, svc.Name, metav1.GetOptions{}) //nolint:staticcheck // Endpoints is still served on every supported cluster
	if err != nil {
		check.Status = doctorWarn
		check.Message = fmt.Sprintf("webhook Service %s/%s has no Endpoints object", namespace, svc.Name)
		return check
	}
	ready := 0
	for _, subset := range endpoints.Subsets {
		ready += len(subset.Addresses)
	}
	if ready == 0 {
		check.Status = doctorWarn
		check.Message = fmt.Sprintf("webhook Service %s/%s has no ready endpoints", namespace, svc.Name)
		check.Remediation = "check the manager pod and its webhook port"
		return check
	}
	check.Status = doctorPass
	check.Message = fmt.Sprintf("webhook Service %s/%s has %d ready endpoint(s)", namespace, svc.Name, ready)
	return check
}

// sortedChecks keeps JSON output deterministic.
func sortedChecks(checks []doctorCheck) []doctorCheck {
	out := append([]doctorCheck(nil), checks...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
