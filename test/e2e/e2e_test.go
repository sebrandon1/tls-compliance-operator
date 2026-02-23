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
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sebrandon1/tls-compliance-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "tls-compliance-operator-system"

// serviceAccountName created for the project
const serviceAccountName = "tls-compliance-operator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "tls-compliance-operator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "tls-compliance-operator-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", managerImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("patching scan interval for faster pod scanning in E2E")
		cmd = exec.Command("kubectl", "patch", "deployment",
			"tls-compliance-operator-controller-manager", "-n", namespace,
			"--type=json", `-p=[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--scan-interval=30s"}]`)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to patch scan interval")

		By("waiting for patched rollout to complete")
		cmd = exec.Command("kubectl", "rollout", "status", "deployment",
			"tls-compliance-operator-controller-manager", "-n", namespace, "--timeout=120s")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to wait for rollout")
	})

	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}
		}
	})

	SetDefaultEventuallyTimeout(5 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).NotTo(BeEmpty(), "controller pod name should not be empty")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should create TLSComplianceReport for HTTPS services", func() {
			By("creating a test service with HTTPS port")
			cmd := exec.Command("kubectl", "create", "service", "clusterip", "test-https",
				"--tcp=443:443", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for TLSComplianceReport to be created")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "expected at least one TLSComplianceReport")
			}).Should(Succeed())

			By("cleaning up test service")
			cmd = exec.Command("kubectl", "delete", "service", "test-https", "-n", "default")
			_, _ = utils.Run(cmd)
		})
	})

	Context("Pod Scanning", func() {
		const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

		It("should create TLSComplianceReport for a pod with TLS port", func() {
			By("creating a pod with port 443")
			cmd := exec.Command("kubectl", "run", "test-tls-pod",
				"--image="+agnhostImage,
				"--port=443",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-tls-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			By("waiting for the pod to be running")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-tls-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			By("waiting for TLSComplianceReport CR with sourceKind=Pod")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceKind},{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Pod,test-tls-pod"),
					"expected a TLSComplianceReport with sourceKind=Pod for test-tls-pod")
			}).Should(Succeed())
		})

		It("should label hostNetwork pod CR with host-network=true", func() {
			By("creating a hostNetwork pod with port 8443")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(`
apiVersion: v1
kind: Pod
metadata:
  name: test-hostnet-pod
  namespace: default
spec:
  hostNetwork: true
  containers:
  - name: agnhost
    image: ` + agnhostImage + `
    command: ["sleep", "3600"]
    ports:
    - containerPort: 8443
`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			// Always clean up the pod, even if the test skips
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-hostnet-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			By("checking if pod can run on Kind")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-hostnet-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				phase := strings.TrimSpace(output)
				// hostNetwork pods may fail to run on Kind; treat non-Running as eventual success
				// so we can check the phase outside Eventually
				g.Expect(phase).NotTo(BeEmpty())
			}).WithTimeout(30 * time.Second).Should(Succeed())

			cmd = exec.Command("kubectl", "get", "pod", "test-hostnet-pod",
				"-o", "jsonpath={.status.phase}")
			phaseOut, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			if strings.TrimSpace(phaseOut) != "Running" {
				Skip("hostNetwork pod cannot run on Kind cluster — skipping")
			}

			By("waiting for TLSComplianceReport CR with host-network label")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-l", "tls-compliance.telco.openshift.io/host-network=true",
					"-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(),
					"expected a TLSComplianceReport with host-network=true label")
			}).Should(Succeed())
		})

		It("should remove TLSComplianceReport when source pod is deleted", func() {
			By("creating a pod with port 443")
			cmd := exec.Command("kubectl", "run", "test-cleanup-pod",
				"--image="+agnhostImage,
				"--port=443",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the pod to be running")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-cleanup-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			By("waiting for TLSComplianceReport CR to appear")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("test-cleanup-pod"))
			}).Should(Succeed())

			By("deleting the source pod")
			cmd = exec.Command("kubectl", "delete", "pod", "test-cleanup-pod", "--grace-period=0", "--force")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the TLSComplianceReport CR to be removed by cleanup loop")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-cleanup-pod"),
					"expected TLSComplianceReport for test-cleanup-pod to be removed")
			}).WithTimeout(6 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should not create TLSComplianceReport for a non-TLS pod", func() {
			By("creating a pod with only port 80 (non-TLS)")
			cmd := exec.Command("kubectl", "run", "test-notls-pod",
				"--image="+agnhostImage,
				"--port=80",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-notls-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			By("waiting for the pod to be running")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-notls-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			By("verifying no TLSComplianceReport is created for the non-TLS pod")
			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-notls-pod"),
					"expected no TLSComplianceReport for non-TLS pod")
			}).WithTimeout(30 * time.Second).WithPolling(5 * time.Second).Should(Succeed())
		})
	})
})
