//go:build e2e
// +build e2e

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

package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/test/utils"
)

// managerDeployment is the operator Deployment that the e2e suites patch.
const managerDeployment = "tls-compliance-operator-controller-manager"

// fastScanArgs are the flags the suite adds so scans happen on test timescales.
// The short retry backoff matters too: Closed/Unreachable are transient, so the
// first check of an idle port would otherwise take minutes of exponential
// backoff before status.checkCount is recorded.
var fastScanArgs = []string{"--scan-interval=30s", "--cleanup-interval=30s", "--workers=20", "--retry-backoff=1s"}

// addManagerArg appends args to the manager container in one patch and waits
// for the rollout.
func addManagerArg(args ...string) {
	patch := managerArgPatch(args)
	cmd := exec.Command("kubectl", "patch", "deployment",
		managerDeployment, "-n", namespace, "--type=json", "-p="+patch)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to add manager args %v", args)
	waitForManagerRollout()
}

// managerArgPatch builds a JSON patch that appends the args to the container.
func managerArgPatch(args []string) string {
	ops := make([]string, 0, len(args))
	for _, arg := range args {
		ops = append(ops, fmt.Sprintf(`{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":%q}`, arg))
	}
	return "[" + strings.Join(ops, ",") + "]"
}

// managerArgs returns the manager container's current args.
func managerArgs(g Gomega) []string {
	cmd := exec.Command("kubectl", "get", "deployment",
		managerDeployment, "-n", namespace,
		"-o", "jsonpath={.spec.template.spec.containers[0].args}")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred())
	return parseManagerArgs(output)
}

// parseManagerArgs splits the jsonpath args list into individual flags.
func parseManagerArgs(output string) []string {
	trimmed := strings.Trim(strings.TrimSpace(output), "[]\"")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\",\"")
}

// ensureManagerArgs adds only the args that are not already present, in one
// patch, and waits for the rollout only when something changed.
func ensureManagerArgs(args ...string) {
	current := managerArgs(Default)
	present := make(map[string]bool, len(current))
	for _, arg := range current {
		present[arg] = true
	}
	var missing []string
	for _, arg := range args {
		if !present[arg] {
			missing = append(missing, arg)
		}
	}
	if len(missing) == 0 {
		return
	}
	cmd := exec.Command("kubectl", "patch", "deployment",
		managerDeployment, "-n", namespace, "--type=json", "-p="+managerArgPatch(missing))
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to ensure manager args %v", missing)
	waitForManagerRollout()
}

func waitForManagerRollout() {
	cmd := exec.Command("kubectl", "rollout", "status", "deployment",
		managerDeployment, "-n", namespace, "--timeout=300s")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to wait for manager rollout")
}

// removeManagerArg removes arg from the manager container and waits for the
// rollout. It is a no-op when the arg is not present.
func removeManagerArg(arg string) {
	// Container cleanup can run after the Manager suite has already
	// undeployed the operator, so a missing Deployment is a no-op.
	cmd := exec.Command("kubectl", "get", "deployment",
		managerDeployment, "-n", namespace,
		"-o", "jsonpath={.spec.template.spec.containers[0].args}")
	output, err := utils.Run(cmd)
	if err != nil {
		return
	}
	args := parseManagerArgs(output)
	for i, a := range args {
		if a != arg {
			continue
		}
		patch := fmt.Sprintf(`[{"op":"remove","path":"/spec/template/spec/containers/0/args/%d"}]`, i)
		cmd := exec.Command("kubectl", "patch", "deployment",
			managerDeployment, "-n", namespace, "--type=json", "-p="+patch)
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "rollout", "status", "deployment",
			managerDeployment, "-n", namespace, "--timeout=300s")
		_, _ = utils.Run(cmd)
		return
	}
}

// ensureManagerDeployed makes the in-cluster operator available with the
// fast-scan args. It is idempotent: an already healthy operator is left alone,
// so specs that undeploy the operator (run-once, dry-run) cannot strand the
// specs that follow them.
func ensureManagerDeployed() {
	By("ensuring the manager namespace exists")
	cmd := exec.Command("kubectl", "create", "ns", namespace)
	if out, err := utils.Run(cmd); err != nil {
		Expect(out).To(ContainSubstring("AlreadyExists"),
			"failed to create manager namespace: %s", out)
	}
	cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
		"pod-security.kubernetes.io/enforce=restricted")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

	By("ensuring CRDs are installed")
	cmd = exec.Command("kubectl", "get", "crd", "tlscompliancereports.security.telco.openshift.io")
	if _, err := utils.Run(cmd); err != nil {
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")
	}

	By("ensuring the controller-manager is deployed")
	cmd = exec.Command("kubectl", "get", "deployment", managerDeployment, "-n", namespace)
	if _, err := utils.Run(cmd); err != nil {
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", managerImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	}

	ensureManagerArgs(fastScanArgs...)
	waitForManagerRollout()

	Eventually(func(g Gomega) {
		out, err := utils.Run(exec.Command("kubectl", "get", "deployment",
			managerDeployment, "-n", namespace, "-o", "jsonpath={.status.readyReplicas}"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal("1"))
	}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
}

// undeployManager removes the in-cluster operator and waits for its Deployment
// and pods to be gone, so a local manager binary cannot race a stale instance.
func undeployManager() {
	By("undeploying the controller-manager")
	cmd := exec.Command("make", "undeploy")
	_, _ = utils.Run(cmd)

	Eventually(func(g Gomega) {
		out, err := utils.Run(exec.Command("kubectl", "get", "deployment",
			managerDeployment, "-n", namespace, "-o", "name"))
		if err != nil {
			g.Expect(out).To(ContainSubstring("NotFound"))
			return
		}
		g.Expect(strings.TrimSpace(out)).To(BeEmpty())
	}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())

	Eventually(func(g Gomega) {
		out, err := utils.Run(exec.Command("kubectl", "get", "pods", "-n", namespace,
			"-l", "control-plane=controller-manager", "-o", "name"))
		if err != nil {
			g.Expect(out).To(ContainSubstring("NotFound"))
			return
		}
		g.Expect(strings.TrimSpace(out)).To(BeEmpty())
	}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
}

// buildManagerBinary installs the CRDs and builds ./bin/manager.
func buildManagerBinary() string {
	By("building the manager binary and installing CRDs")
	cmd := exec.Command("make", "install", "build")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "make install build failed")
	return filepath.Join(projectRoot(), "bin", "manager")
}

// scrapeMetrics returns the operator's Prometheus metrics. It binds the
// metrics-reader role to the manager service account, mints a token, and
// reads the secure endpoint through a port-forward.
func scrapeMetrics(g Gomega) string {
	cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
		"--clusterrole=tls-compliance-operator-metrics-reader",
		"--serviceaccount="+namespace+":"+serviceAccountName)
	if out, err := utils.Run(cmd); err != nil {
		// kubectl reports a conflict as `... "<name>" already exists`.
		g.Expect(out).To(ContainSubstring("already exists"))
	}

	cmd = exec.Command("kubectl", "create", "token", serviceAccountName, "-n", namespace)
	token, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred())

	const localPort = 18443
	pf := exec.Command("kubectl", "port-forward", "-n", namespace,
		"svc/"+metricsServiceName, strconv.Itoa(localPort)+":8443")
	g.Expect(pf.Start()).To(Succeed())
	defer func() { _ = pf.Process.Kill(); _ = pf.Wait() }()

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed metrics cert in Kind
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/metrics", localPort), nil)
	g.Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))

	var body []byte
	g.Eventually(func(g Gomega) {
		resp, err := client.Do(req)
		g.Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err = io.ReadAll(resp.Body)
		g.Expect(err).NotTo(HaveOccurred())
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
	return string(body)
}

// metricSum adds up every sample of the named metric in a Prometheus text dump.
func metricSum(g Gomega, dump, name string) float64 {
	var sum float64
	for _, line := range strings.Split(dump, "\n") {
		if !strings.HasPrefix(line, name+"{") && !strings.HasPrefix(line, name+" ") {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		g.Expect(err).NotTo(HaveOccurred(), "parse %q", line)
		sum += v
	}
	return sum
}

// metricValue returns the value of the named metric for the exact label set.
// A metric that is absent returns 0, which makes "series disappeared"
// assertions possible for gauges.
func metricValue(g Gomega, dump, name string, labels map[string]string) float64 {
	for _, line := range strings.Split(dump, "\n") {
		if !strings.HasPrefix(line, name) || strings.HasPrefix(line, "#") {
			continue
		}
		rest := strings.TrimPrefix(line, name)
		if rest != "" && rest[0] != '{' && rest[0] != ' ' {
			continue
		}
		labelSet := ""
		if strings.HasPrefix(rest, "{") {
			end := strings.LastIndex(rest, "}")
			g.Expect(end).To(BeNumerically(">", 0), "malformed metric line %q", line)
			labelSet = rest[1:end]
			rest = rest[end+1:]
		}
		if !metricLabelsMatch(labelSet, labels) {
			continue
		}
		fields := strings.Fields(rest)
		g.Expect(fields).NotTo(BeEmpty(), "malformed metric line %q", line)
		v, err := strconv.ParseFloat(fields[0], 64)
		g.Expect(err).NotTo(HaveOccurred(), "parse %q", line)
		return v
	}
	return 0
}

// metricLabelsMatch reports whether a Prometheus label set contains every
// label/value pair in want.
func metricLabelsMatch(labelSet string, want map[string]string) bool {
	got := make(map[string]string)
	for _, pair := range splitMetricLabels(labelSet) {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		got[strings.TrimSpace(key)] = strings.Trim(value, `"`)
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

// splitMetricLabels splits on commas that are not inside a quoted value.
func splitMetricLabels(labelSet string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	for i := 0; i < len(labelSet); i++ {
		switch c := labelSet[i]; {
		case c == '"':
			inQuotes = !inQuotes
			current.WriteByte(c)
		case c == ',' && !inQuotes:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// buildPlugin builds the kubectl-tlsreport plugin into a temp dir and returns its path.
func buildPlugin() string {
	bin := filepath.Join(GinkgoT().TempDir(), "kubectl-tlsreport")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/kubectl-tlsreport/")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to build kubectl-tlsreport plugin")
	return bin
}

// listReports returns every TLSComplianceReport in the cluster.
func listReports(g Gomega) []securityv1alpha1.TLSComplianceReport {
	out, err := utils.Run(exec.Command("kubectl", "get", "tlsreport", "-o", "json"))
	g.Expect(err).NotTo(HaveOccurred(), "failed to list reports: %s", out)
	var list securityv1alpha1.TLSComplianceReportList
	g.Expect(json.Unmarshal([]byte(out), &list)).To(Succeed(), "failed to decode reports")
	return list.Items
}

// findReports returns the reports matching the source identity and port.
func findReports(g Gomega, kind securityv1alpha1.SourceKind, ns, name string, port int32) []securityv1alpha1.TLSComplianceReport {
	var matches []securityv1alpha1.TLSComplianceReport
	for _, report := range listReports(g) {
		if report.Spec.SourceKind == kind &&
			report.Spec.SourceNamespace == ns &&
			report.Spec.SourceName == name &&
			report.Spec.Port == port {
			matches = append(matches, report)
		}
	}
	return matches
}

// getReport returns one report by name.
func getReport(g Gomega, name string) securityv1alpha1.TLSComplianceReport {
	out, err := utils.Run(exec.Command("kubectl", "get", "tlsreport", name, "-o", "json"))
	g.Expect(err).NotTo(HaveOccurred(), "failed to get report %s: %s", name, out)
	var report securityv1alpha1.TLSComplianceReport
	g.Expect(json.Unmarshal([]byte(out), &report)).To(Succeed(), "failed to decode report %s", name)
	return report
}

// getTarget returns one TLSComplianceTarget by name.
func getTarget(g Gomega, name string) securityv1alpha1.TLSComplianceTarget {
	out, err := utils.Run(exec.Command("kubectl", "get", "tlstarget", name, "-o", "json"))
	g.Expect(err).NotTo(HaveOccurred(), "failed to get target %s: %s", name, out)
	var target securityv1alpha1.TLSComplianceTarget
	g.Expect(json.Unmarshal([]byte(out), &target)).To(Succeed(), "failed to decode target %s", name)
	return target
}

// waitForCheckedReport waits for a report matching the source identity that has
// completed at least one check, and returns it.
func waitForCheckedReport(g Gomega, kind securityv1alpha1.SourceKind, ns, name string, port int32) securityv1alpha1.TLSComplianceReport {
	reports := findReports(g, kind, ns, name, port)
	g.Expect(reports).NotTo(BeEmpty(), "no %s/%s/%s:%d report yet", kind, ns, name, port)
	report := reports[0]
	g.Expect(report.Status.CheckCount).To(BeNumerically(">=", 1),
		"%s/%s/%s:%d has not completed a check yet", kind, ns, name, port)
	cond := apimeta.FindStatusCondition(report.Status.Conditions, "Available")
	g.Expect(cond).NotTo(BeNil(), "report %s has no Available condition", report.Name)
	g.Expect(cond.Status).To(Equal(metav1.ConditionTrue), "report %s is not Available", report.Name)
	g.Expect(cond.Reason).To(Equal("EndpointDiscovered"), "report %s Available reason = %q", report.Name, cond.Reason)
	return report
}

// findCondition returns the named status condition.
func findCondition(report securityv1alpha1.TLSComplianceReport, conditionType string) *metav1.Condition {
	return apimeta.FindStatusCondition(report.Status.Conditions, conditionType)
}

// findTargetCondition returns the named target status condition.
func findTargetCondition(target securityv1alpha1.TLSComplianceTarget, conditionType string) *metav1.Condition {
	return apimeta.FindStatusCondition(target.Status.Conditions, conditionType)
}

// expectCondition asserts a condition's status and reason.
func expectCondition(report securityv1alpha1.TLSComplianceReport, conditionType string, status metav1.ConditionStatus, reason string) {
	cond := findCondition(report, conditionType)
	ExpectWithOffset(1, cond).NotTo(BeNil(), "report %s has no %s condition", report.Name, conditionType)
	ExpectWithOffset(1, cond.Status).To(Equal(status), "%s condition on %s", conditionType, report.Name)
	ExpectWithOffset(1, cond.Reason).To(Equal(reason), "%s condition reason on %s", conditionType, report.Name)
}

// reportEventExists reports whether an event with the given reason exists for
// the involved object.
func reportEventExists(g Gomega, reason, involvedName string) bool {
	out, err := utils.Run(exec.Command("kubectl", "get", "events", "-A",
		"--field-selector", fmt.Sprintf("reason=%s,involvedObject.name=%s", reason, involvedName),
		"-o", "name"))
	g.Expect(err).NotTo(HaveOccurred(), "failed to list %s events: %s", reason, out)
	return len(utils.GetNonEmptyLines(out)) > 0
}

// podIPs returns every IP assigned to a pod.
func podIPs(g Gomega, ns, name string) []string {
	out, err := utils.Run(exec.Command("kubectl", "get", "pod", name, "-n", ns,
		"-o", `jsonpath={range .status.podIPs[*]}{.ip}{"\n"}{end}`))
	g.Expect(err).NotTo(HaveOccurred(), "failed to get pod IPs for %s/%s", ns, name)
	return utils.GetNonEmptyLines(out)
}

// countTLSReports returns the number of TLSComplianceReport objects.
func countTLSReports() int {
	cmd := exec.Command("kubectl", "get", "tlsreport", "-o", "jsonpath={.items[*].metadata.name}")
	out, err := utils.Run(cmd)
	if err != nil {
		return 0
	}
	return len(strings.Fields(string(out)))
}

// tlsReportNames returns the names of all TLSComplianceReport objects.
func tlsReportNames(g Gomega) []string {
	out, err := utils.Run(exec.Command("kubectl", "get", "tlsreport", "-o", "name"))
	g.Expect(err).NotTo(HaveOccurred())
	return utils.GetNonEmptyLines(out)
}
