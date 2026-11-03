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

	"github.com/sebrandon1/tls-compliance-operator/test/utils"
)

// managerDeployment is the operator Deployment that the e2e suites patch.
const managerDeployment = "tls-compliance-operator-controller-manager"

// addManagerArg appends args to the manager container in one patch and waits
// for the rollout.
func addManagerArg(args ...string) {
	ops := make([]string, 0, len(args))
	for _, arg := range args {
		ops = append(ops, fmt.Sprintf(`{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":%q}`, arg))
	}
	cmd := exec.Command("kubectl", "patch", "deployment",
		managerDeployment, "-n", namespace, "--type=json", "-p=["+strings.Join(ops, ",")+"]")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to add manager args %v", args)
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
	cmd := exec.Command("kubectl", "get", "deployment",
		managerDeployment, "-n", namespace,
		"-o", "jsonpath={.spec.template.spec.containers[0].args}")
	output, err := utils.Run(cmd)
	if err != nil {
		return
	}
	args := strings.Split(strings.Trim(output, "[]\""), "\",\"")
	for i, a := range args {
		if a != arg {
			continue
		}
		patch := fmt.Sprintf(`[{"op":"remove","path":"/spec/template/spec/containers/0/args/%d"}]`, i)
		cmd = exec.Command("kubectl", "patch", "deployment",
			managerDeployment, "-n", namespace, "--type=json", "-p="+patch)
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "rollout", "status", "deployment",
			managerDeployment, "-n", namespace, "--timeout=300s")
		_, _ = utils.Run(cmd)
		return
	}
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

// buildPlugin builds the kubectl-tlsreport plugin into a temp dir and returns its path.
func buildPlugin() string {
	bin := filepath.Join(GinkgoT().TempDir(), "kubectl-tlsreport")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/kubectl-tlsreport/")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to build kubectl-tlsreport plugin")
	return bin
}
