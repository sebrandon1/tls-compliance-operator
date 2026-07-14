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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
				Port                  int
				Env                   map[string]string
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
				g.Expect(output).To(ContainSubstring(name+"."+testNS+",8443"))
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
				g.Expect(output).To(ContainSubstring(name+"."+testNS+",0"))
			}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "events",
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
				Port                  int
				Env                   map[string]string
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
				Port                  int
				Env                   map[string]string
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

		It("should report NoTLS for plain HTTP on a TLS port", func() {
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
					fmt.Sprintf("%s.%s,%d,%s", name, testNS, 8443, "NoTLS")))
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
	})
})
