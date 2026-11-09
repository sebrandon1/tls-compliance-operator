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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sebrandon1/tls-compliance-operator/test/utils"
)

func manifestPath(name string) string {
	return filepath.Join(projectRoot(), "test", "e2e", "manifests", name)
}

func loadManifest(name string) string {
	data, err := os.ReadFile(manifestPath(name))
	Expect(err).NotTo(HaveOccurred(), "Failed to read manifest %s", name)
	return string(data)
}

func renderManifest(name string, data any) string {
	tmpl, err := template.ParseFiles(manifestPath(name))
	Expect(err).NotTo(HaveOccurred(), "Failed to parse template %s", name)
	var buf bytes.Buffer
	Expect(tmpl.Execute(&buf, data)).To(Succeed(), "Failed to render template %s", name)
	return buf.String()
}

func kubectlApplyManifest(manifest, description string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to apply %s", description)
}

var testServerImage = "quay.io/bapalm/tls-test-server:latest"

func init() {
	if img := os.Getenv("TEST_SERVER_IMG"); img != "" {
		testServerImage = img
	}
}

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

		By("patching scan and cleanup intervals for faster E2E execution")
		cmd = exec.Command("kubectl", "patch", "deployment",
			"tls-compliance-operator-controller-manager", "-n", namespace,
			"--type=json", `-p=[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--scan-interval=30s"},{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--cleanup-interval=30s"},{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--workers=20"}]`)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to patch scan interval")

		By("waiting for patched rollout to complete")
		cmd = exec.Command("kubectl", "rollout", "status", "deployment",
			"tls-compliance-operator-controller-manager", "-n", namespace, "--timeout=300s")
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
			// controllerPodName is only set by the manager specs and goes stale
			// after a restart, so read the current pod through the Deployment.
			cmd := exec.Command("kubectl", "logs", "deployment/"+managerDeployment, "-n", namespace)
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

	Context("Manager", Label("manager"), func() {
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
	})

	// =========================================================================
	// POSITIVE TESTS — verify reports ARE created for valid TLS resources
	// =========================================================================

	Context("Positive: Service Detection", Label("service-detection"), func() {
		It("should create report for a Service on port 443", func() {
			cmd := exec.Command("kubectl", "create", "service", "clusterip", "test-https",
				"--tcp=443:443", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "service", "test-https", "-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty())
			}).Should(Succeed())
		})

		It("should create report for a Service on port 9443", func() {
			cmd := exec.Command("kubectl", "create", "service", "clusterip", "test-webhook-svc",
				"--tcp=9443:9443", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "service", "test-webhook-svc", "-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host},{.spec.port}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("test-webhook-svc.default,9443"))
			}).Should(Succeed())
		})

		It("should create report for a Service on port 2379", func() {
			cmd := exec.Command("kubectl", "create", "service", "clusterip", "test-etcd-svc",
				"--tcp=2379:2379", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "service", "test-etcd-svc", "-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host},{.spec.port}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("test-etcd-svc.default,2379"))
			}).Should(Succeed())
		})
	})

	Context("Positive: ExternalName Service Detection", Label("service-detection"), func() {
		It("should create report for an ExternalName Service", func() {
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(`apiVersion: v1
kind: Service
metadata:
  name: test-external-api
  namespace: default
spec:
  type: ExternalName
  externalName: kubernetes.default.svc.cluster.local
`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "service", "test-external-api",
					"-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host},{.spec.port},{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("kubernetes.default.svc.cluster.local,443,test-external-api"))
			}).Should(Succeed())
		})
	})

	Context("Positive: Pod Detection", Label("pod-detection"), func() {
		const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

		It("should create report for a pod with TLS port", func() {
			cmd := exec.Command("kubectl", "run", "test-tls-pod",
				"--image="+agnhostImage, "--port=443",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-tls-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-tls-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceKind},{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Pod,test-tls-pod"))
			}).Should(Succeed())
		})

		It("should label hostNetwork pod CR with host-network=true", func() {
			manifest := renderManifest("hostnetwork-pod.yaml", map[string]string{"Image": agnhostImage})
			kubectlApplyManifest(manifest, "hostNetwork pod")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-hostnet-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-hostnet-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).NotTo(BeEmpty())
			}).WithTimeout(30 * time.Second).Should(Succeed())

			phaseCmd := exec.Command("kubectl", "get", "pod", "test-hostnet-pod",
				"-o", "jsonpath={.status.phase}")
			phaseOut, err := utils.Run(phaseCmd)
			Expect(err).NotTo(HaveOccurred())
			if strings.TrimSpace(phaseOut) != "Running" {
				Skip("hostNetwork pod cannot run on Kind cluster")
			}

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-l", "tls-compliance.telco.openshift.io/host-network=true", "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty())
			}).Should(Succeed())
		})
	})

	Context("Positive: Ingress Detection", Label("ingress-detection"), func() {
		It("should create report for an Ingress with TLS", func() {
			kubectlApplyManifest(loadManifest("tls-ingress.yaml"), "TLS Ingress")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "ingress", "test-tls-ingress",
					"-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceKind},{.spec.host}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Ingress,test-app.example.com"))
			}).Should(Succeed())
		})
	})

	Context("Positive: TLSComplianceTarget", Label("target-detection"), func() {
		It("should create report for a custom target", func() {
			kubectlApplyManifest(loadManifest("tlscompliancetarget.yaml"), "TLSComplianceTarget")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "tlstarget", "test-k8s-api", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceKind},{.spec.host}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Target,kubernetes.default.svc"))
			}).Should(Succeed())
		})
	})

	Context("Positive: Compliance Status Validation", Label("compliance-validation"), Ordered, func() {
		const testNS = "tls-e2e-validation"

		BeforeAll(func() {
			cmd := exec.Command("kubectl", "create", "ns", testNS)
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNS,
				"pod-security.kubernetes.io/enforce=privileged")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "ns", testNS, "--ignore-not-found", "--timeout=60s")
			_, _ = utils.Run(cmd)
		})

		deployTestServer := func(name string, port int, env map[string]string) {
			manifest := renderManifest("testserver-pod.yaml", struct {
				Name, Namespace, Image string
				Port                   int
				Env                    map[string]string
			}{name, testNS, testServerImage, port, env})
			kubectlApplyManifest(manifest, "test server pod "+name)
		}

		createTestService := func(name string, port int) {
			manifest := renderManifest("testserver-service.yaml", struct {
				Name, Namespace string
				Port            int
			}{name, testNS, port})
			kubectlApplyManifest(manifest, "test server service "+name)
		}

		waitForPodRunning := func(name string) {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", name, "-n", testNS,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}

		waitForReportWithStatus := func(host string, port int, expectedStatus string) {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", "jsonpath={range .items[*]}{.spec.host},{.spec.port},{.status.complianceStatus}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(
					fmt.Sprintf("%s.%s,%d,%s", host, testNS, port, expectedStatus)))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		}

		It("should report Compliant for a TLS 1.2+1.3 endpoint", func() {
			name := "test-compliant"
			deployTestServer(name, 8443, map[string]string{
				"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.3",
			})
			createTestService(name, 8443)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			waitForReportWithStatus(name, 8443, "Compliant")
		})

		It("should report Compliant for a MySQL STARTTLS endpoint", func() {
			name := "test-starttls-mysql"
			deployTestServer(name, 3306, map[string]string{
				"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.3",
				"LISTEN_PORT": "3306", "STARTTLS_PROTOCOL": "mysql",
			})
			createTestService(name, 3306)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			waitForReportWithStatus(name, 3306, "Compliant")
		})

		It("should report Compliant for a Sieve STARTTLS endpoint", func() {
			name := "test-starttls-sieve"
			deployTestServer(name, 4190, map[string]string{
				"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.3",
				"LISTEN_PORT": "4190", "STARTTLS_PROTOCOL": "sieve",
			})
			createTestService(name, 4190)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			waitForReportWithStatus(name, 4190, "Compliant")
		})

		It("should create report for mTLS endpoint", func() {
			name := "test-mtls"
			deployTestServer(name, 8443, map[string]string{"MTLS_REQUIRED": "true"})
			createTestService(name, 8443)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", "jsonpath={range .items[*]}{.spec.host},{.spec.port}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(name + "." + testNS + ",8443"))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})

		It("should detect near-expiry certificate and emit warning event", func() {
			name := "test-expiring-cert"
			deployTestServer(name, 8443, map[string]string{"CERT_EXPIRY_HOURS": "1"})
			createTestService(name, 8443)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", "jsonpath={range .items[*]}{.spec.host},{.status.certificateInfo.daysUntilExpiry}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(name + "." + testNS + ",0"))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "events.events.k8s.io",
					"--field-selector", "reason=CertificateExpiring",
					"-o", "jsonpath={.items[*].reason}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("CertificateExpiring"))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})
	})

	// =========================================================================
	// ML-KEM PROBING TESTS — verify active post-quantum key exchange detection
	// =========================================================================

	Context("ML-KEM Active Probing", Label("compliance-positive"), func() {
		const testNS = "tls-e2e-mlkem"

		BeforeAll(func() {
			cmd := exec.Command("kubectl", "create", "ns", testNS)
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNS,
				"pod-security.kubernetes.io/enforce=privileged")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "ns", testNS, "--ignore-not-found", "--timeout=60s")
			_, _ = utils.Run(cmd)
		})

		deployTestServer := func(name string, port int, env map[string]string) {
			manifest := renderManifest("testserver-pod.yaml", struct {
				Name, Namespace, Image string
				Port                   int
				Env                    map[string]string
			}{name, testNS, testServerImage, port, env})
			kubectlApplyManifest(manifest, "test server pod "+name)
		}

		createTestService := func(name string, port int) {
			manifest := renderManifest("testserver-service.yaml", struct {
				Name, Namespace string
				Port            int
			}{name, testNS, port})
			kubectlApplyManifest(manifest, "test server service "+name)
		}

		waitForPodRunning := func(name string) {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", name, "-n", testNS,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}

		It("should report PQCReady and mlkemSupported=true for ML-KEM capable endpoint", func() {
			name := "test-mlkem-enabled"
			deployTestServer(name, 8443, map[string]string{
				"TLS_MIN_VERSION": "1.3", "TLS_MAX_VERSION": "1.3",
			})
			createTestService(name, 8443)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", "jsonpath={range .items[*]}{.spec.host},{.spec.port},{.status.pqcReadiness},{.status.mlkemSupported}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(
					fmt.Sprintf("%s.%s,%d,%s,%s", name, testNS, 8443, "PQCReady", "true")))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})

		It("should report TLS13Capable and mlkemSupported=false when ML-KEM is disabled", func() {
			name := "test-mlkem-disabled"
			deployTestServer(name, 8443, map[string]string{
				"TLS_MIN_VERSION": "1.3", "TLS_MAX_VERSION": "1.3",
				"DISABLE_MLKEM": "true",
			})
			createTestService(name, 8443)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", "jsonpath={range .items[*]}{.spec.host},{.spec.port},{.status.pqcReadiness},{.status.mlkemSupported}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(
					fmt.Sprintf("%s.%s,%d,%s,%s", name, testNS, 8443, "TLS13Capable", "false")))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})
	})

	// =========================================================================
	// NEGATIVE TESTS — verify reports are NOT created or are cleaned up
	// =========================================================================

	Context("Negative: Non-TLS Resources Ignored", Label("non-tls-ignored"), func() {
		const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

		It("should not create report for a pod on port 80", func() {
			cmd := exec.Command("kubectl", "run", "test-notls-pod",
				"--image="+agnhostImage, "--port=80",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-notls-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-notls-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-notls-pod"))
			}).WithTimeout(30 * time.Second).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should not create report for a Service on non-TLS port 9090", func() {
			cmd := exec.Command("kubectl", "create", "service", "clusterip", "test-grpc-svc",
				"--tcp=9090:9090", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "service", "test-grpc-svc",
					"-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-grpc-svc"))
			}).WithTimeout(30 * time.Second).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should not create report for an Ingress without TLS", func() {
			kubectlApplyManifest(loadManifest("non-tls-ingress.yaml"), "non-TLS Ingress")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "ingress", "test-notls-ingress",
					"-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-plain.example.com"))
			}).WithTimeout(30 * time.Second).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should not create report for a pod on port 3000", func() {
			cmd := exec.Command("kubectl", "run", "test-app-pod",
				"--image="+agnhostImage, "--port=3000",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-app-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-app-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-app-pod"))
			}).WithTimeout(30 * time.Second).WithPolling(5 * time.Second).Should(Succeed())
		})
	})

	Context("Scan All Ports", Label("scan-all-ports"), func() {
		const agnhostImageSAP = "registry.k8s.io/e2e-test-images/agnhost:2.53"

		It("should create report for a pod on non-standard port 3000 when scan-all-ports is enabled", func() {
			By("creating the test pod before enabling scan-all-ports")
			cmd := exec.Command("kubectl", "run", "test-scanall-pod",
				"--image="+agnhostImageSAP, "--port=3000",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-scanall-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-scanall-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			By("enabling --scan-all-ports on the operator")
			cmd = exec.Command("kubectl", "patch", "deployment",
				"tls-compliance-operator-controller-manager", "-n", namespace,
				"--type=json",
				`-p=[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--scan-all-ports"}]`)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for rollout with scan-all-ports")
			cmd = exec.Command("kubectl", "rollout", "status", "deployment",
				"tls-compliance-operator-controller-manager", "-n", namespace, "--timeout=300s")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				By("removing --scan-all-ports from the operator")
				cmd := exec.Command("kubectl", "get", "deployment",
					"tls-compliance-operator-controller-manager", "-n", namespace,
					"-o", "jsonpath={.spec.template.spec.containers[0].args}")
				output, err := utils.Run(cmd)
				if err != nil {
					return
				}
				args := strings.Split(strings.Trim(output, "[]\""), "\",\"")
				for i, arg := range args {
					if arg == "--scan-all-ports" {
						patch := fmt.Sprintf(`[{"op":"remove","path":"/spec/template/spec/containers/0/args/%d"}]`, i)
						cmd = exec.Command("kubectl", "patch", "deployment",
							"tls-compliance-operator-controller-manager", "-n", namespace,
							"--type=json", "-p="+patch)
						_, _ = utils.Run(cmd)
						cmd = exec.Command("kubectl", "rollout", "status", "deployment",
							"tls-compliance-operator-controller-manager", "-n", namespace, "--timeout=300s")
						_, _ = utils.Run(cmd)
						break
					}
				}
			})

			By("waiting for the operator to scan the non-standard port pod")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("test-scanall-pod"))
			}).WithTimeout(180 * time.Second).WithPolling(10 * time.Second).Should(Succeed())
		})
	})

	Context("Negative: Compliance Status Detection", Label("compliance-detection"), Ordered, func() {
		const testNS = "tls-e2e-validation"

		BeforeAll(func() {
			cmd := exec.Command("kubectl", "create", "ns", testNS)
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNS,
				"pod-security.kubernetes.io/enforce=privileged")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "ns", testNS, "--ignore-not-found", "--timeout=60s")
			_, _ = utils.Run(cmd)
		})

		deployTestServer := func(name string, port int, env map[string]string) {
			manifest := renderManifest("testserver-pod.yaml", struct {
				Name, Namespace, Image string
				Port                   int
				Env                    map[string]string
			}{name, testNS, testServerImage, port, env})
			kubectlApplyManifest(manifest, "test server pod "+name)
		}

		createTestService := func(name string, port int) {
			manifest := renderManifest("testserver-service.yaml", struct {
				Name, Namespace string
				Port            int
			}{name, testNS, port})
			kubectlApplyManifest(manifest, "test server service "+name)
		}

		waitForPodRunning := func(name string) {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", name, "-n", testNS,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}

		It("should report PlaintextHTTP for plain HTTP on a TLS port", func() {
			name := "test-notls-http"
			deployTestServer(name, 8443, map[string]string{
				"TLS_ENABLED": "false", "LISTEN_PORT": "8443",
			})
			createTestService(name, 8443)
			waitForPodRunning(name)
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", testNS, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", "jsonpath={range .items[*]}{.spec.host},{.spec.port},{.status.complianceStatus}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(
					fmt.Sprintf("%s.%s,%d,%s", name, testNS, 8443, "PlaintextHTTP")))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})
	})

	Context("Negative: Cleanup", Label("cleanup"), func() {
		const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

		It("should remove report when source pod is deleted", func() {
			cmd := exec.Command("kubectl", "run", "test-cleanup-pod",
				"--image="+agnhostImage, "--port=443",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-cleanup-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("test-cleanup-pod"))
			}).Should(Succeed())

			cmd = exec.Command("kubectl", "delete", "pod", "test-cleanup-pod", "--grace-period=0", "--force")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceName}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-cleanup-pod"))
			}).WithTimeout(8 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should remove report when source Service is deleted", func() {
			cmd := exec.Command("kubectl", "create", "service", "clusterip", "test-cleanup-svc",
				"--tcp=443:443", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("test-cleanup-svc"))
			}).Should(Succeed())

			cmd = exec.Command("kubectl", "delete", "service", "test-cleanup-svc", "-n", "default")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("test-cleanup-svc"))
			}).WithTimeout(8 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})
	})

	Context("kubectl-tlsreport plugin", Label("plugin"), func() {
		var pluginBinary string

		BeforeAll(func() {
			By("building the kubectl-tlsreport plugin")
			cmd := exec.Command("go", "build", "-o", "/tmp/kubectl-tlsreport", "./cmd/kubectl-tlsreport/")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to build kubectl-tlsreport plugin")
			pluginBinary = "/tmp/kubectl-tlsreport"

			By("creating test services for sort validation")
			for _, name := range []string{"zulu-svc", "alpha-svc", "mike-svc"} {
				cmd := exec.Command("kubectl", "create", "service", "clusterip", name,
					"--tcp=443:443", "-n", "default")
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to create service "+name)
			}

			By("waiting for TLSComplianceReports to be created for all test services")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.host}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("alpha-svc"))
				g.Expect(output).To(ContainSubstring("mike-svc"))
				g.Expect(output).To(ContainSubstring("zulu-svc"))
			}).Should(Succeed())
		})

		AfterAll(func() {
			for _, name := range []string{"zulu-svc", "alpha-svc", "mike-svc"} {
				cmd := exec.Command("kubectl", "delete", "service", name, "-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}
		})

		It("should sort reports by host", func() {
			cmd := exec.Command(pluginBinary, "csv", "--sort-by", "host")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport csv --sort-by host")

			lines := strings.Split(strings.TrimSpace(output), "\n")
			Expect(len(lines)).To(BeNumerically(">=", 4), "expected header + at least 3 data rows")

			var hosts []string
			for _, line := range lines[1:] {
				fields := strings.Split(line, ",")
				if len(fields) > 0 {
					hosts = append(hosts, fields[0])
				}
			}

			for i := 1; i < len(hosts); i++ {
				Expect(hosts[i] >= hosts[i-1]).To(BeTrue(),
					fmt.Sprintf("hosts not sorted: %q should come after %q", hosts[i], hosts[i-1]))
			}
		})

		It("should produce valid JSON with --sort-by", func() {
			cmd := exec.Command(pluginBinary, "json", "--sort-by", "host")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport json --sort-by host")
			Expect(output).To(HavePrefix("["), "expected JSON array output")
		})

		It("should produce a valid Markdown table", func() {
			cmd := exec.Command(pluginBinary, "md")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport md")

			lines := strings.Split(strings.TrimSpace(output), "\n")
			Expect(len(lines)).To(BeNumerically(">=", 3), "expected header + separator + at least 1 data row")
			Expect(lines[0]).To(HavePrefix("| Host"))
			Expect(lines[1]).To(ContainSubstring("---"))

			for _, line := range lines {
				Expect(line).To(HavePrefix("|"), "each line should start with pipe")
				Expect(line).To(HaveSuffix("|"), "each line should end with pipe")
			}
		})

		It("should show TLS-Capable Endpoints in summary output", func() {
			cmd := exec.Command(pluginBinary, "summary")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport summary")

			Expect(output).To(ContainSubstring("Total Endpoints:"),
				"summary should show Total Endpoints")
			Expect(output).To(ContainSubstring("TLS-Capable Endpoints:"),
				"summary should show TLS-Capable Endpoints count")
			Expect(output).To(ContainSubstring("Compliance Rate:"),
				"summary should show Compliance Rate")
		})

		It("should show the next scan ETA in report and table output", func() {
			By("verifying the report status contains a future next scan time")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					`jsonpath={range .items[?(@.spec.sourceName=="alpha-svc")]}{.status.nextScanAt}{"\n"}{end}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				nextScanAt, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(output))
				g.Expect(parseErr).NotTo(HaveOccurred(), "nextScanAt should be an RFC3339 timestamp")
				g.Expect(nextScanAt).To(BeTemporally(">", time.Now()))
			}).Should(Succeed())

			By("verifying the default table includes the next scan column")
			cmd := exec.Command(pluginBinary, "get")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport get")
			Expect(output).To(ContainSubstring("NEXT SCAN"))

			By("verifying wide table output includes the next scan column")
			cmd = exec.Command(pluginBinary, "get", "-o", "wide")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport get -o wide")
			Expect(output).To(ContainSubstring("NEXT SCAN"))
		})
	})

	Context("Namespace Filter on Existing Reports", Label("namespace-filter"), Ordered, func() {
		const (
			keepNS      = "tls-e2e-ns-keep"
			dropNS      = "tls-e2e-ns-drop"
			svcName     = "ns-filter-svc"
			lateTarget  = "ns-filter-late-target"
			includeFlag = "--include-namespaces=" + keepNS
			// Exclude-mode phase: keepNS becomes the filtered namespace and
			// cleanup is paused so its report stays around to be ignored.
			excludeFlag  = "--exclude-namespaces=" + keepNS
			blankInclude = "--include-namespaces= , "
			pauseCleanup = "--cleanup-interval=1h"
			perEndpoint  = "--metrics-per-endpoint=true"
			rescanKey    = "tls-compliance.telco.openshift.io/rescan"
			k8sAPITarget = "test-k8s-api"
			sharedSvc    = "shared-tls"
			sharedHost   = sharedSvc + "." + dropNS
			sharedLabel  = `host="` + sharedHost + `"`
			// The Services have no backing pods, so the first check of a
			// recreated report would retry for minutes while holding the
			// report's in-flight claim and defer the rescan past its timeout.
			noRetries = "--max-retries=0"
		)

		reportName := func(g Gomega, ns string) string {
			cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
				"jsonpath={.items[?(@.spec.sourceNamespace==\""+ns+"\")].metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			names := strings.Fields(output)
			g.Expect(names).To(HaveLen(1), "reports in %s: %v", ns, names)
			return names[0]
		}

		reportSources := func(g Gomega) string {
			cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
				"jsonpath={range .items[*]}{.spec.sourceKind},{.spec.sourceNamespace},{.spec.sourceName}{\"\\n\"}{end}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			return output
		}

		BeforeAll(func() {
			By("creating a TLS Service in two namespaces and a TLSComplianceTarget before any filter is set")
			for _, ns := range []string{keepNS, dropNS} {
				cmd := exec.Command("kubectl", "create", "ns", ns)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				cmd = exec.Command("kubectl", "create", "service", "clusterip", svcName,
					"--tcp=443:443", "-n", ns)
				_, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
			}
			kubectlApplyManifest(loadManifest("tlscompliancetarget.yaml"), "TLSComplianceTarget")

			DeferCleanup(func() {
				for _, arg := range []string{includeFlag, excludeFlag, blankInclude, pauseCleanup, noRetries, perEndpoint} {
					removeManagerArg(arg)
				}
				cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName, "--ignore-not-found")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "delete", "tlstarget", k8sAPITarget, lateTarget, "--ignore-not-found")
				_, _ = utils.Run(cmd)
				for _, ns := range []string{keepNS, dropNS} {
					cmd = exec.Command("kubectl", "delete", "ns", ns, "--ignore-not-found", "--timeout=60s")
					_, _ = utils.Run(cmd)
				}
			})

			Eventually(func(g Gomega) {
				output := reportSources(g)
				g.Expect(output).To(ContainSubstring("Service," + keepNS + "," + svcName))
				g.Expect(output).To(ContainSubstring("Service," + dropNS + "," + svcName))
				g.Expect(output).To(ContainSubstring("Target,cluster-scoped,test-k8s-api"))
			}).Should(Succeed())
		})

		It("should delete existing reports outside --include-namespaces added after the first start", func() {
			By("adding --include-namespaces to the running operator")
			addManagerArg(includeFlag)

			By("waiting for cleanup to remove the report from the filtered namespace")
			Eventually(func(g Gomega) {
				g.Expect(reportSources(g)).NotTo(ContainSubstring("Service," + dropNS + "," + svcName))
			}).WithTimeout(3 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())

			By("verifying the included namespace report and the cluster-scoped Target report remain")
			Consistently(func(g Gomega) {
				output := reportSources(g)
				g.Expect(output).To(ContainSubstring("Service," + keepNS + "," + svcName))
				g.Expect(output).To(ContainSubstring("Target,cluster-scoped,test-k8s-api"))
				g.Expect(output).NotTo(ContainSubstring("Service," + dropNS + "," + svcName))
			}).WithTimeout(time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})

		It("should reconcile a TLSComplianceTarget created while --include-namespaces is set", func() {
			kubectlApplyManifest(fmt.Sprintf(`apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceTarget
metadata:
  name: %s
spec:
  host: kubernetes.default.svc
  port: 443
`, lateTarget), "TLSComplianceTarget")

			Eventually(func(g Gomega) {
				g.Expect(reportSources(g)).To(ContainSubstring("Target,cluster-scoped," + lateTarget))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should honor the rescan annotation on a report inside --include-namespaces", func() {
			cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
				"jsonpath={.items[?(@.spec.sourceNamespace==\""+keepNS+"\")].metadata.name}")
			name, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			name = strings.TrimSpace(name)
			Expect(name).NotTo(BeEmpty())

			cmd = exec.Command("kubectl", "annotate", "tlsreport", name,
				rescanKey+"=true", "--overwrite")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the operator to consume the annotation")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", name, "-o", "jsonpath={.metadata.annotations}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring(rescanKey))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should ignore filtered reports in exclude mode for rescans, the gauge, the plugin and blank flags", func() {
			By("switching to --exclude-namespaces with a blank --include-namespaces and cleanup paused")
			removeManagerArg(includeFlag)
			addManagerArg(pauseCleanup, noRetries, excludeFlag, blankInclude)

			By("warning about the blank include flag without claiming it takes precedence")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", "deployment/"+managerDeployment, "-n", namespace)
				logs, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(logs).To(ContainSubstring(`--include-namespaces " , " contains no namespace names and is ignored`))
				g.Expect(logs).NotTo(ContainSubstring("--include-namespaces takes precedence"))
			}).WithTimeout(time.Minute).WithPolling(5 * time.Second).Should(Succeed())

			By("recreating the report for the namespace that is now inside the filter")
			var dropReport, keepReport string
			Eventually(func(g Gomega) {
				dropReport = reportName(g, dropNS)
				keepReport = reportName(g, keepNS)
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())

			By("counting only reports inside the filter in tls_compliance_endpoints_total")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
					"jsonpath={range .items[*]}{.spec.sourceNamespace}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				inFilter := 0
				for _, ns := range utils.GetNonEmptyLines(output) {
					if ns != keepNS {
						inFilter++
					}
				}
				g.Expect(metricSum(g, scrapeMetrics(g), "tls_compliance_endpoints_total")).To(BeNumerically("==", inFilter))
			}).WithTimeout(3 * time.Minute).WithPolling(15 * time.Second).Should(Succeed())

			plugin := buildPlugin()

			By("completing a plugin rescan --wait on a report inside the filter")
			cmd := exec.Command(plugin, "rescan", dropReport, "--wait", "--timeout=2m")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), output)
			Expect(output).To(ContainSubstring("Rescan complete for " + dropReport))

			By("ignoring a rescan on the filtered report and recording RescanSkipped")
			cmd = exec.Command(plugin, "rescan", keepReport, "--wait", "--timeout=15s")
			output, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred())
			Expect(output).To(ContainSubstring("outside the operator's namespace filter"))
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "events", "-A",
					"--field-selector", "reason=RescanSkipped,involvedObject.name="+keepReport, "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(utils.GetNonEmptyLines(output)).NotTo(BeEmpty())
			}).WithTimeout(time.Minute).WithPolling(5 * time.Second).Should(Succeed())
			cmd = exec.Command("kubectl", "get", "tlsreport", keepReport, "-o", "jsonpath={.metadata.annotations}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring(rescanKey), "the skipped rescan must leave its annotation")

			By("reporting a report deleted during plugin rescan --wait")
			wait := exec.Command(plugin, "rescan", keepReport, "--wait", "--timeout=2m")
			var waitOut bytes.Buffer
			wait.Stdout, wait.Stderr = &waitOut, &waitOut
			Expect(wait.Start()).To(Succeed())
			time.Sleep(3 * time.Second)
			cmd = exec.Command("kubectl", "delete", "tlsreport", keepReport)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(wait.Wait()).To(HaveOccurred())
			Expect(waitOut.String()).To(ContainSubstring("was deleted before its rescan finished"))
		})

		It("should keep per-endpoint metrics while another report covers the same host:port", func() {
			// A Service and an Ingress whose TLS host is the Service's name
			// both produce reports for sharedHost:443. Targets cannot be used
			// here: their dials refuse private addresses such as ClusterIPs.
			// The Ingress shares the Service's name to cover #650: both kinds
			// must be discovered even though their requests have the same key.
			By("resuming cleanup and enabling per-endpoint metrics")
			removeManagerArg(pauseCleanup)
			addManagerArg(perEndpoint)

			By("serving TLS behind a Service and an Ingress with the same host")
			kubectlApplyManifest(renderManifest("testserver-pod.yaml", struct {
				Name, Namespace, Image string
				Port                   int
				Env                    map[string]string
			}{sharedSvc, dropNS, testServerImage, 8443, nil}), "test server pod "+sharedSvc)
			kubectlApplyManifest(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  selector:
    app: %[1]s
  ports:
  - name: https
    port: 443
    targetPort: 8443
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  tls:
  - hosts:
    - %[3]s
  defaultBackend:
    service:
      name: %[1]s
      port:
        number: 443
`, sharedSvc, dropNS, sharedHost), "shared Service and Ingress")
			Eventually(func(g Gomega) {
				output := reportSources(g)
				g.Expect(output).To(ContainSubstring("Service," + dropNS + "," + sharedSvc))
				g.Expect(output).To(ContainSubstring("Ingress," + dropNS + "," + sharedSvc))
				g.Expect(scrapeMetrics(g)).To(ContainSubstring(sharedLabel))
			}).WithTimeout(3 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())

			By("deleting the Ingress while the Service still covers the endpoint")
			cmd := exec.Command("kubectl", "delete", "ingress", sharedSvc, "-n", dropNS)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(reportSources(g)).NotTo(ContainSubstring("Ingress," + dropNS + "," + sharedSvc))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
			Consistently(func(g Gomega) {
				g.Expect(scrapeMetrics(g)).To(ContainSubstring(sharedLabel))
			}).WithTimeout(30 * time.Second).WithPolling(10 * time.Second).Should(Succeed())

			By("deleting the Service, the last report for the endpoint")
			cmd = exec.Command("kubectl", "delete", "service,pod", sharedSvc, "-n", dropNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(scrapeMetrics(g)).NotTo(ContainSubstring(sharedLabel))
			}).WithTimeout(2 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})
	})

	Context("Periodic Scan Retry Stall", Label("retry-stall"), Ordered, func() {
		const (
			agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"
			podName      = "retry-stall-pod"
			fastBackoff  = "--retry-backoff=1s"
			slowBackoff  = "--retry-backoff=5m"
		)

		// minClosedCheckCount asserts that the pod has at least one report and that
		// every one is Closed, then returns the lowest checkCount. A pod gets one
		// report per IP (dual-stack clusters give it two), and checkCount is
		// omitted until the first check completes.
		minClosedCheckCount := func(g Gomega) int {
			cmd := exec.Command("kubectl", "get", "tlsreport", "-o",
				"jsonpath={range .items[?(@.spec.sourceName==\""+podName+"\")]}{.status.complianceStatus},{.status.checkCount}{\"\\n\"}{end}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			lines := utils.GetNonEmptyLines(output)
			g.Expect(lines).NotTo(BeEmpty(), "no report for %s yet", podName)
			lowest := -1
			for _, line := range lines {
				status, count, _ := strings.Cut(line, ",")
				g.Expect(status).To(Equal("Closed"), "report line %q", line)
				n := 0
				if count != "" {
					n, err = strconv.Atoi(count)
					g.Expect(err).NotTo(HaveOccurred())
				}
				if lowest < 0 || n < lowest {
					lowest = n
				}
			}
			return lowest
		}

		BeforeAll(func() {
			DeferCleanup(func() {
				removeManagerArg(slowBackoff)
				removeManagerArg(fastBackoff)
				cmd := exec.Command("kubectl", "delete", "pod", podName,
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			By("using a short retry backoff so the discovery check finishes quickly")
			addManagerArg(fastBackoff)

			By("creating a pod that declares port 443 but does not listen on it")
			cmd := exec.Command("kubectl", "run", podName, "--image="+agnhostImage, "--port=443",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the discovery check, retries included, to complete")
			Eventually(func(g Gomega) {
				g.Expect(minClosedCheckCount(g)).To(BeNumerically(">=", 1))
			}).WithTimeout(3 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should keep scanning while an endpoint refuses connections", func() {
			By("restarting with a retry backoff longer than the test window")
			// The last --retry-backoff wins; the report already exists, so only the periodic scan probes it.
			addManagerArg(slowBackoff)

			var start int
			Eventually(func(g Gomega) { start = minClosedCheckCount(g) }).Should(Succeed())

			By("waiting for two periodic passes to re-probe the endpoint without sleeping through backoff")
			// --scan-interval=30s. Inline retries would hold the first pass for 5m+ instead.
			Eventually(func(g Gomega) {
				g.Expect(minClosedCheckCount(g)).To(BeNumerically(">=", start+2))
			}).WithTimeout(2 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})
	})

	Context("Run-Once Mode", Label("run-once"), Ordered, func() {
		var managerBin string

		BeforeAll(func() {
			By("undeploying the in-cluster operator to prevent interference")
			cmd := exec.Command("make", "undeploy")
			_, _ = utils.Run(cmd)

			By("deleting all existing TLSComplianceReport CRs")
			cmd = exec.Command("kubectl", "delete", "tlsreport", "--all", "--ignore-not-found")
			_, _ = utils.Run(cmd)

			By("building the manager binary and installing CRDs once")
			cmd = exec.Command("make", "install", "build")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "make install build failed")
			managerBin = filepath.Join(projectRoot(), "bin", "manager")
		})

		runOnceAndReadOutput := func(filename, format string, extraArgs ...string) []byte {
			outputFile := filepath.Join(os.TempDir(), filename)
			DeferCleanup(os.Remove, outputFile)
			args := append([]string{
				"--run-once",
				"--output-format=" + format,
				"--output-file=" + outputFile,
			}, extraArgs...)

			GinkgoWriter.Printf("run-once: format=%s file=%s args=%v\n", format, filename, extraArgs)
			start := time.Now()

			cmd := exec.Command(managerBin, args...)
			output, err := utils.Run(cmd)

			GinkgoWriter.Printf("run-once: completed in %s (format=%s)\n", time.Since(start).Round(time.Millisecond), format)

			Expect(err).NotTo(HaveOccurred(), "run-once failed: %s", output)
			data, err := os.ReadFile(outputFile)
			Expect(err).NotTo(HaveOccurred(), "failed to read results file")
			GinkgoWriter.Printf("run-once: output file size=%d bytes\n", len(data))
			return data
		}

		It("should scan and produce JUnit output", func() {
			data := runOnceAndReadOutput("e2e-run-once-results.xml", "junit")
			Expect(string(data)).To(ContainSubstring("<testsuites"), "expected JUnit XML output")
		})

		It("should produce JSON output", func() {
			data := runOnceAndReadOutput("e2e-run-once-results.json", "json")
			Expect(string(data)).To(HavePrefix("["), "expected JSON array output")
		})

		It("should support namespace filtering", func() {
			data := runOnceAndReadOutput("e2e-run-once-ns-results.xml", "junit",
				"--include-namespaces=default")
			Expect(string(data)).To(ContainSubstring("<testsuites"), "expected JUnit XML output")
		})

		It("should leave non-compliant reports outside --include-namespaces out of the output and exit code", func() {
			const leftoverNS = "tls-e2e-run-once-leftover"
			By("creating a NonCompliant report left over from an earlier, unfiltered run")
			kubectlApplyManifest(`apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceReport
metadata:
  name: e2e-run-once-leftover
spec:
  host: leftover.example.com
  port: 443
  sourceKind: Service
  sourceNamespace: `+leftoverNS+`
  sourceName: gone
`, "leftover TLSComplianceReport")
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "tlsreport", "e2e-run-once-leftover", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			cmd := exec.Command("kubectl", "patch", "tlsreport", "e2e-run-once-leftover",
				"--subresource=status", "--type=merge", `-p={"status":{"complianceStatus":"NonCompliant"}}`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			// runOnceAndReadOutput fails on a non-zero exit, so this also checks
			// that the leftover NonCompliant report does not set exit code 1.
			data := runOnceAndReadOutput("e2e-run-once-ns-results.json", "json", "--include-namespaces=default")
			var results []struct {
				Namespace string `json:"namespace"`
			}
			Expect(json.Unmarshal(data, &results)).To(Succeed())
			for _, r := range results {
				Expect(r.Namespace).To(Equal("default"))
			}
		})

		It("kubectl tlsreport --fail-on-non-compliant should exit 0 when all compliant", func() {
			pluginBinary := filepath.Join(os.TempDir(), "kubectl-tlsreport-runonce")
			DeferCleanup(os.Remove, pluginBinary)

			cmd := exec.Command("go", "build", "-o", pluginBinary, "./cmd/kubectl-tlsreport/")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to build kubectl-tlsreport plugin")

			cmd = exec.Command(pluginBinary, "summary", "--fail-on-non-compliant")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "summary --fail-on-non-compliant should exit 0 when all endpoints are compliant")
		})
	})
})
