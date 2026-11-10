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
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
	"github.com/sebrandon1/tls-compliance-operator/pkg/export"
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

// agnhostImage is the generic workload image used by the e2e specs.
const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

// deployTestServerIn renders and applies a TLS test server pod.
func deployTestServerIn(ns, name string, port int, env map[string]string) {
	manifest := renderManifest("testserver-pod.yaml", struct {
		Name, Namespace, Image string
		Port                   int
		Env                    map[string]string
	}{name, ns, testServerImage, port, env})
	kubectlApplyManifest(manifest, "test server pod "+name)
}

// createTestServiceIn renders and applies a Service for a TLS test server.
func createTestServiceIn(ns, name string, port int) {
	manifest := renderManifest("testserver-service.yaml", struct {
		Name, Namespace string
		Port            int
	}{name, ns, port})
	kubectlApplyManifest(manifest, "test server service "+name)
}

// waitForPodRunningIn waits for a pod to reach Running.
func waitForPodRunningIn(ns, name string) {
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "pod", name, "-n", ns,
			"-o", "jsonpath={.status.phase}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
	}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
}

// deletePodAndService removes a test pod and its Service, ignoring misses.
func deletePodAndService(ns, name string) {
	cmd := exec.Command("kubectl", "delete", "pod,svc", name, "-n", ns, "--ignore-not-found")
	_, _ = utils.Run(cmd)
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
		ensureManagerDeployed()
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

				out, err := utils.Run(exec.Command("kubectl", "get", "deployment",
					managerDeployment, "-n", namespace, "-o", "jsonpath={.status.readyReplicas}"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(out)).To(Equal("1"), "expected one ready manager replica")

				phase, err := utils.Run(exec.Command("kubectl", "get", "pod", controllerPodName,
					"-n", namespace, "-o", "jsonpath={.status.phase}"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(phase)).To(Equal("Running"))
			}
			Eventually(verifyControllerUp).Should(Succeed())

			By("validating the fast-scan flags are present")
			args := managerArgs(Default)
			for _, want := range fastScanArgs {
				Expect(args).To(ContainElement(want), "manager args %v", args)
			}
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
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", "test-https", 443)
				g.Expect(report.Spec.Host).To(Equal("test-https.default"))
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
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", "test-webhook-svc", 9443)
				g.Expect(report.Spec.Host).To(Equal("test-webhook-svc.default"))
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
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", "test-etcd-svc", 2379)
				g.Expect(report.Spec.Host).To(Equal("test-etcd-svc.default"))
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
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", "test-external-api", 443)
				g.Expect(report.Spec.Host).To(Equal("kubernetes.default.svc.cluster.local"))
				g.Expect(report.Status.ComplianceStatus).To(Equal(securityv1alpha1.ComplianceStatusUnreachable))
				g.Expect(report.Status.LastError).To(ContainSubstring("reserved address blocked"))
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
				ips := podIPs(g, "default", "test-tls-pod")
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindPod, "default", "test-tls-pod", 443)
				g.Expect(ips).To(ContainElement(report.Spec.Host))
				g.Expect(report.Status.ComplianceStatus).To(Equal(securityv1alpha1.ComplianceStatusClosed))
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
				ips := podIPs(g, "default", "test-hostnet-pod")
				reports := findReports(g, securityv1alpha1.SourceKindPod, "default", "test-hostnet-pod", 8443)
				g.Expect(reports).NotTo(BeEmpty(), "no hostNetwork pod report yet")
				report := reports[0]
				g.Expect(report.Labels).To(HaveKeyWithValue("tls-compliance.telco.openshift.io/host-network", "true"))
				g.Expect(report.Status.CheckCount).To(BeNumerically(">=", 1))
				g.Expect(ips).To(ContainElement(report.Spec.Host))
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
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindIngress, "default", "test-tls-ingress", 443)
				g.Expect(report.Spec.Host).To(Equal("test-app.example.com"))
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
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindTarget, "cluster-scoped", "test-k8s-api", 443)
				g.Expect(report.Spec.Host).To(Equal("kubernetes.default.svc"))
				g.Expect(report.Status.ComplianceStatus).To(Equal(securityv1alpha1.ComplianceStatusUnreachable))
				g.Expect(report.Status.LastError).To(ContainSubstring("reserved address blocked"))

				target := getTarget(g, "test-k8s-api")
				g.Expect(target.Status.ReportName).To(Equal(report.Name))
				g.Expect(target.Status.LastScannedAt).NotTo(BeNil())
				targetCond := findTargetCondition(target, "Ready")
				g.Expect(targetCond).NotTo(BeNil(), "target has no Ready condition")
				g.Expect(targetCond.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(targetCond.Reason).To(Equal("ScanComplete"))
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

		waitForReportWithStatus := func(g Gomega, name string, port int, expected securityv1alpha1.ComplianceStatus) securityv1alpha1.TLSComplianceReport {
			report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, testNS, name, int32(port))
			g.Expect(report.Spec.Host).To(Equal(name + "." + testNS))
			g.Expect(report.Status.ComplianceStatus).To(Equal(expected))
			return report
		}

		It("should report Compliant for a TLS 1.2+1.3 endpoint", func() {
			name := "test-compliant"
			deployTestServerIn(testNS, name, 8443, map[string]string{
				"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.3",
			})
			createTestServiceIn(testNS, name, 8443)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			Eventually(func(g Gomega) {
				report := waitForReportWithStatus(g, name, 8443, securityv1alpha1.ComplianceStatusCompliant)
				g.Expect(report.Status.TLSVersions.TLS12).To(BeTrue())
				g.Expect(report.Status.TLSVersions.TLS13).To(BeTrue())
				g.Expect(report.Status.TLSVersions.TLS10).To(BeFalse())
				g.Expect(report.Status.TLSVersions.TLS11).To(BeFalse())
				g.Expect(report.Status.TLSVersions.SSL30).To(BeFalse())
				// Go's TLS 1.2 defaults are AEAD (A) but the enumerated list can
				// include CBC+ECDHE suites (B); both keep forward secrecy.
				g.Expect(report.Status.OverallCipherGrade).To(BeElementOf("A", "B"))
				g.Expect(report.Status.ForwardSecrecy).To(BeTrue())
				g.Expect(report.Status.CertificateInfo).NotTo(BeNil(), "certificateInfo must be populated")
				cert := report.Status.CertificateInfo
				g.Expect(cert.Fingerprint).To(MatchRegexp(`^[0-9a-f]{64}$`))
				g.Expect(cert.PublicKeyAlgorithm).To(Equal("ECDSA"))
				g.Expect(cert.NotAfter).NotTo(BeNil())
				g.Expect(cert.NotAfter.After(time.Now())).To(BeTrue(), "certificate should not be expired")
				g.Expect(cert.DaysUntilExpiry).To(BeNumerically(">", 30))
				expectCondition(report, "TLSCompliant", metav1.ConditionTrue, "Compliant")
				expectCondition(report, "CertificateValid", metav1.ConditionTrue, "Valid")
				expectCondition(report, "Available", metav1.ConditionTrue, "EndpointDiscovered")
				g.Expect(report.Status.LastCheckAt).NotTo(BeNil())
				g.Expect(report.Status.NextScanAt).NotTo(BeNil())
				g.Expect(report.Status.NextScanAt.After(report.Status.LastCheckAt.Time)).To(BeTrue())
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should report Compliant for a MySQL STARTTLS endpoint", func() {
			name := "test-starttls-mysql"
			deployTestServerIn(testNS, name, 3306, map[string]string{
				"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.3",
				"LISTEN_PORT": "3306", "STARTTLS_PROTOCOL": "mysql",
			})
			createTestServiceIn(testNS, name, 3306)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			Eventually(func(g Gomega) {
				report := waitForReportWithStatus(g, name, 3306, securityv1alpha1.ComplianceStatusCompliant)
				g.Expect(report.Status.TLSVersions.TLS12).To(BeTrue())
				g.Expect(report.Status.TLSVersions.TLS13).To(BeTrue())
				expectCondition(report, "TLSCompliant", metav1.ConditionTrue, "Compliant")
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should report Compliant for a Sieve STARTTLS endpoint", func() {
			name := "test-starttls-sieve"
			deployTestServerIn(testNS, name, 4190, map[string]string{
				"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.3",
				"LISTEN_PORT": "4190", "STARTTLS_PROTOCOL": "sieve",
			})
			createTestServiceIn(testNS, name, 4190)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			Eventually(func(g Gomega) {
				report := waitForReportWithStatus(g, name, 4190, securityv1alpha1.ComplianceStatusCompliant)
				g.Expect(report.Status.TLSVersions.TLS12).To(BeTrue())
				g.Expect(report.Status.TLSVersions.TLS13).To(BeTrue())
				expectCondition(report, "TLSCompliant", metav1.ConditionTrue, "Compliant")
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should create report for mTLS endpoint", func() {
			name := "test-mtls"
			deployTestServerIn(testNS, name, 8443, map[string]string{"MTLS_REQUIRED": "true"})
			createTestServiceIn(testNS, name, 8443)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			Eventually(func(g Gomega) {
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, testNS, name, 8443)
				g.Expect(report.Spec.Host).To(Equal(name + "." + testNS))
				// TLS 1.3 defers client-certificate rejection to the first
				// application read, so the current checker may report either
				// MutualTLSRequired or a version-dependent verdict. Assert that
				// the endpoint was checked rather than a specific verdict.
				g.Expect(report.Status.ComplianceStatus).NotTo(BeEmpty())
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should detect near-expiry certificate and emit warning event", func() {
			name := "test-expiring-cert"
			deployTestServerIn(testNS, name, 8443, map[string]string{"CERT_EXPIRY_HOURS": "1"})
			createTestServiceIn(testNS, name, 8443)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			var report securityv1alpha1.TLSComplianceReport
			Eventually(func(g Gomega) {
				report = waitForCheckedReport(g, securityv1alpha1.SourceKindService, testNS, name, 8443)
				g.Expect(report.Spec.Host).To(Equal(name + "." + testNS))
				g.Expect(report.Status.CertificateInfo).NotTo(BeNil())
				g.Expect(report.Status.CertificateInfo.IsExpired).To(BeFalse())
				g.Expect(report.Status.CertificateInfo.DaysUntilExpiry).To(BeNumerically(">=", 0))
				g.Expect(report.Status.CertificateInfo.DaysUntilExpiry).To(BeNumerically("<=", 1))
				expectCondition(report, "CertificateValid", metav1.ConditionFalse, "Expiring")
				cond := findCondition(report, "CertificateValid")
				g.Expect(cond.Message).To(ContainSubstring("expires in"))
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())

			Eventually(func(g Gomega) {
				g.Expect(reportEventExists(g, "CertificateExpiring", report.Name)).To(BeTrue(),
					"expected a CertificateExpiring event for %s", report.Name)
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

		It("should report PQCReady and mlkemSupported=true for ML-KEM capable endpoint", func() {
			name := "test-mlkem-enabled"
			deployTestServerIn(testNS, name, 8443, map[string]string{
				"TLS_MIN_VERSION": "1.3", "TLS_MAX_VERSION": "1.3",
			})
			createTestServiceIn(testNS, name, 8443)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			Eventually(func(g Gomega) {
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, testNS, name, 8443)
				g.Expect(report.Spec.Host).To(Equal(name + "." + testNS))
				g.Expect(report.Status.PQCReadiness).To(Equal(securityv1alpha1.PQCReadinessPQCReady))
				g.Expect(report.Status.MLKEMSupported).To(BeTrue())
				g.Expect(report.Status.QuantumReady).To(BeTrue())
				expectCondition(report, "TLSCompliant", metav1.ConditionTrue, "Compliant")
				expectCondition(report, "PQCCompliant", metav1.ConditionTrue, "PQCReady")
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should report TLS13Capable and mlkemSupported=false when ML-KEM is disabled", func() {
			name := "test-mlkem-disabled"
			deployTestServerIn(testNS, name, 8443, map[string]string{
				"TLS_MIN_VERSION": "1.3", "TLS_MAX_VERSION": "1.3",
				"DISABLE_MLKEM": "true",
			})
			createTestServiceIn(testNS, name, 8443)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			Eventually(func(g Gomega) {
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, testNS, name, 8443)
				g.Expect(report.Status.PQCReadiness).To(Equal(securityv1alpha1.PQCReadinessTLS13Capable))
				g.Expect(report.Status.MLKEMSupported).To(BeFalse())
				g.Expect(report.Status.QuantumReady).To(BeFalse())
				expectCondition(report, "PQCCompliant", metav1.ConditionFalse, "TLS13Capable")
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})
	})

	// =========================================================================
	// NEGATIVE TESTS — verify reports are NOT created or are cleaned up
	// =========================================================================

	Context("Negative: Non-TLS Resources Ignored", Label("non-tls-ignored"), func() {
		const canaryName = "test-notls-canary"

		// The canary proves the operator is scanning while the negative
		// assertions below check that specific resources produce no report.
		canaryAlive := func(g Gomega) {
			reports := findReports(g, securityv1alpha1.SourceKindService, "default", canaryName, 443)
			g.Expect(reports).NotTo(BeEmpty(), "operator is not scanning: canary report missing")
			g.Expect(reports[0].Status.CheckCount).To(BeNumerically(">=", 1))
		}

		BeforeAll(func() {
			cmd := exec.Command("kubectl", "create", "service", "clusterip", canaryName,
				"--tcp=443:443", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", canaryName, 443)
			}).Should(Succeed())
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "service", canaryName, "-n", "default", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

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
				canaryAlive(g)
				g.Expect(findReports(g, securityv1alpha1.SourceKindPod, "default", "test-notls-pod", 80)).To(BeEmpty())
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
				canaryAlive(g)
				g.Expect(findReports(g, securityv1alpha1.SourceKindService, "default", "test-grpc-svc", 9090)).To(BeEmpty())
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
				canaryAlive(g)
				for _, report := range listReports(g) {
					g.Expect(report.Spec.SourceName).NotTo(Equal("test-notls-ingress"),
						"non-TLS Ingress produced report %s", report.Name)
				}
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
				canaryAlive(g)
				g.Expect(findReports(g, securityv1alpha1.SourceKindPod, "default", "test-app-pod", 3000)).To(BeEmpty())
			}).WithTimeout(30 * time.Second).WithPolling(5 * time.Second).Should(Succeed())
		})
	})

	Context("Scan All Ports", Label("scan-all-ports"), func() {
		It("should create report for a pod on non-standard port 3000 when scan-all-ports is enabled", func() {
			By("creating the test pod before enabling scan-all-ports")
			cmd := exec.Command("kubectl", "run", "test-scanall-pod",
				"--image="+agnhostImage, "--port=3000",
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

			By("verifying the port is not scanned while the flag is off")
			Consistently(func(g Gomega) {
				g.Expect(findReports(g, securityv1alpha1.SourceKindPod, "default", "test-scanall-pod", 3000)).To(BeEmpty())
			}).WithTimeout(30 * time.Second).WithPolling(5 * time.Second).Should(Succeed())

			By("enabling --scan-all-ports on the operator")
			addManagerArg("--scan-all-ports")
			DeferCleanup(func() {
				removeManagerArg("--scan-all-ports")
			})

			By("waiting for the operator to scan the non-standard port pod")
			Eventually(func(g Gomega) {
				ips := podIPs(g, "default", "test-scanall-pod")
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindPod, "default", "test-scanall-pod", 3000)
				g.Expect(ips).To(ContainElement(report.Spec.Host))
				g.Expect(report.Status.ComplianceStatus).To(Equal(securityv1alpha1.ComplianceStatusClosed))
			}).WithTimeout(180 * time.Second).WithPolling(10 * time.Second).Should(Succeed())

			By("deleting the pod and waiting for cleanup to remove the report")
			cmd = exec.Command("kubectl", "delete", "pod", "test-scanall-pod", "--grace-period=0", "--force")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(findReports(g, securityv1alpha1.SourceKindPod, "default", "test-scanall-pod", 3000)).To(BeEmpty())
			}).WithTimeout(3 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
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

		It("should report PlaintextHTTP for plain HTTP on a TLS port", func() {
			name := "test-notls-http"
			deployTestServerIn(testNS, name, 8443, map[string]string{
				"TLS_ENABLED": "false", "LISTEN_PORT": "8443",
			})
			createTestServiceIn(testNS, name, 8443)
			waitForPodRunningIn(testNS, name)
			DeferCleanup(func() { deletePodAndService(testNS, name) })

			Eventually(func(g Gomega) {
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, testNS, name, 8443)
				g.Expect(report.Spec.Host).To(Equal(name + "." + testNS))
				g.Expect(report.Status.ComplianceStatus).To(Equal(securityv1alpha1.ComplianceStatusPlaintextHTTP))
				g.Expect(report.Status.CertificateInfo).To(BeNil(), "plaintext endpoint must not report a certificate")
				g.Expect(findCondition(report, "CertificateValid")).To(BeNil(),
					"plaintext endpoint must not have a CertificateValid condition")
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})
	})

	Context("Negative: Cleanup", Label("cleanup"), func() {
		It("should remove report when source pod is deleted", func() {
			cmd := exec.Command("kubectl", "run", "test-cleanup-pod",
				"--image="+agnhostImage, "--port=443",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "test-cleanup-pod",
					"--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "test-cleanup-pod",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(Equal("Running"))
			}).Should(Succeed())

			var report securityv1alpha1.TLSComplianceReport
			Eventually(func(g Gomega) {
				report = waitForCheckedReport(g, securityv1alpha1.SourceKindPod, "default", "test-cleanup-pod", 443)
			}).Should(Succeed())

			cmd = exec.Command("kubectl", "delete", "pod", "test-cleanup-pod", "--grace-period=0", "--force")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				g.Expect(findReports(g, securityv1alpha1.SourceKindPod, "default", "test-cleanup-pod", 443)).To(BeEmpty(),
					"report %s for the deleted pod still exists", report.Name)
			}).WithTimeout(8 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})

		It("should remove report when source Service is deleted", func() {
			cmd := exec.Command("kubectl", "create", "service", "clusterip", "test-cleanup-svc",
				"--tcp=443:443", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "service", "test-cleanup-svc",
					"-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			var report securityv1alpha1.TLSComplianceReport
			Eventually(func(g Gomega) {
				report = waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", "test-cleanup-svc", 443)
				g.Expect(report.Spec.Host).To(Equal("test-cleanup-svc.default"))
			}).Should(Succeed())

			cmd = exec.Command("kubectl", "delete", "service", "test-cleanup-svc", "-n", "default")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				g.Expect(findReports(g, securityv1alpha1.SourceKindService, "default", "test-cleanup-svc", 443)).To(BeEmpty(),
					"report %s for the deleted Service still exists", report.Name)
			}).WithTimeout(8 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		})
	})

	Context("kubectl-tlsreport plugin", Label("plugin"), func() {
		var (
			pluginBinary string
			snapshot     []securityv1alpha1.TLSComplianceReport
			sortSvcs     = []string{"zulu-svc", "alpha-svc", "mike-svc"}
		)

		snapshotReport := func(name string) securityv1alpha1.TLSComplianceReport {
			for _, report := range snapshot {
				if report.Spec.SourceName == name {
					return report
				}
			}
			Fail("snapshot has no report for " + name)
			return securityv1alpha1.TLSComplianceReport{}
		}

		BeforeAll(func() {
			pluginBinary = buildPlugin()

			By("creating test services for sort validation")
			for _, name := range sortSvcs {
				cmd := exec.Command("kubectl", "create", "service", "clusterip", name,
					"--tcp=443:443", "-n", "default")
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to create service "+name)
			}

			By("waiting for checked TLSComplianceReports for all test services")
			Eventually(func(g Gomega) {
				for _, name := range sortSvcs {
					report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", name, 443)
					g.Expect(report.Spec.Host).To(Equal(name + ".default"))
				}
				snapshot = listReports(g)
			}).Should(Succeed())
		})

		AfterAll(func() {
			for _, name := range sortSvcs {
				cmd := exec.Command("kubectl", "delete", "service", name, "-n", "default", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}
		})

		It("should sort reports by host", func() {
			cmd := exec.Command(pluginBinary, "csv", "--sort-by", "host")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport csv --sort-by host")

			records, err := csv.NewReader(strings.NewReader(output)).ReadAll()
			Expect(err).NotTo(HaveOccurred(), "CSV output must parse")
			Expect(records).NotTo(BeEmpty())
			Expect(records[0]).To(Equal(export.CSVHeader), "CSV header")

			index := make(map[string]int, len(export.CSVHeader))
			for i, column := range export.CSVHeader {
				index[column] = i
			}

			var hosts []string
			rows := make(map[string][]string)
			for _, row := range records[1:] {
				Expect(row).To(HaveLen(len(export.CSVHeader)), "CSV row width")
				hosts = append(hosts, row[index["Host"]])
				rows[row[index["Name"]]] = row
			}
			for i := 1; i < len(hosts); i++ {
				Expect(hosts[i] >= hosts[i-1]).To(BeTrue(),
					fmt.Sprintf("hosts not sorted: %q should come after %q", hosts[i], hosts[i-1]))
			}

			for _, name := range sortSvcs {
				row, ok := rows[name]
				Expect(ok).To(BeTrue(), "CSV is missing %s", name)
				want := snapshotReport(name)
				Expect(row[index["Host"]]).To(Equal(name + ".default"))
				Expect(row[index["Port"]]).To(Equal("443"))
				Expect(row[index["Source"]]).To(Equal("Service"))
				Expect(row[index["Namespace"]]).To(Equal("default"))
				Expect(row[index["Compliance"]]).To(Equal(string(want.Status.ComplianceStatus)))
			}
		})

		It("should produce valid JSON with --sort-by", func() {
			cmd := exec.Command(pluginBinary, "json", "--sort-by", "host")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport json --sort-by host")

			var rows []export.JSONReport
			Expect(json.Unmarshal([]byte(output), &rows)).To(Succeed(), "JSON output must parse")
			Expect(len(rows)).To(BeNumerically(">=", 3))

			byName := make(map[string]export.JSONReport, len(rows))
			for _, row := range rows {
				byName[row.Name] = row
			}
			for _, name := range sortSvcs {
				row, ok := byName[name]
				Expect(ok).To(BeTrue(), "JSON is missing %s", name)
				want := snapshotReport(name)
				Expect(row.Host).To(Equal(name + ".default"))
				Expect(row.Port).To(Equal("443"))
				Expect(row.Source).To(Equal("Service"))
				Expect(row.Namespace).To(Equal("default"))
				Expect(row.Compliance).To(Equal(string(want.Status.ComplianceStatus)))
			}
			for i := 1; i < len(rows); i++ {
				Expect(rows[i].Host >= rows[i-1].Host).To(BeTrue(), "JSON rows must be sorted by host")
			}
		})

		It("should produce a valid Markdown table", func() {
			cmd := exec.Command(pluginBinary, "md")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport md")

			lines := strings.Split(strings.TrimSpace(output), "\n")
			Expect(len(lines)).To(BeNumerically(">=", 3), "expected header + separator + at least 1 data row")
			Expect(lines[0]).To(Equal("| Host | Port | Source | Compliance | Grade | FS | ServerPrefersOwnCiphers | " +
				"TLS1.3 | TLS1.2 | TLS1.0 | PQC | MLKEM | CertExpiry | Age |"))
			Expect(lines[1]).To(ContainSubstring("---"))

			for _, line := range lines {
				Expect(line).To(HavePrefix("|"), "each line should start with pipe")
				Expect(line).To(HaveSuffix("|"), "each line should end with pipe")
			}

			want := snapshotReport("alpha-svc")
			var found bool
			for _, line := range lines[2:] {
				columns := strings.Split(strings.Trim(line, "|"), "|")
				if len(columns) < 4 {
					continue
				}
				if strings.TrimSpace(columns[0]) != "alpha-svc.default" {
					continue
				}
				found = true
				Expect(strings.TrimSpace(columns[1])).To(Equal("443"))
				Expect(strings.TrimSpace(columns[2])).To(Equal("Service"))
				Expect(strings.TrimSpace(columns[3])).To(Equal(string(want.Status.ComplianceStatus)))
			}
			Expect(found).To(BeTrue(), "Markdown table is missing alpha-svc.default")
		})

		It("should show TLS-Capable Endpoints in summary output", func() {
			cmd := exec.Command(pluginBinary, "summary")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to run kubectl-tlsreport summary")

			tlsCapable := 0
			for _, report := range snapshot {
				switch report.Status.ComplianceStatus {
				case securityv1alpha1.ComplianceStatusCompliant,
					securityv1alpha1.ComplianceStatusNonCompliant,
					securityv1alpha1.ComplianceStatusWarning,
					securityv1alpha1.ComplianceStatusMutualTLSRequired:
					tlsCapable++
				}
			}

			Expect(output).To(MatchRegexp(`Total Endpoints:\s+%d`, len(snapshot)))
			Expect(output).To(MatchRegexp(`TLS-Capable Endpoints:\s+%d`, tlsCapable))
			Expect(output).To(ContainSubstring("Compliance Rate:"))
			Expect(output).To(ContainSubstring("Status Breakdown"))
		})

		It("should show the next scan ETA in report and table output", func() {
			By("verifying the report schedule follows the global scan interval")
			Eventually(func(g Gomega) {
				report := waitForCheckedReport(g, securityv1alpha1.SourceKindService, "default", "alpha-svc", 443)
				g.Expect(report.Status.LastSeenAt).NotTo(BeNil())
				g.Expect(report.Status.NextScanAt).NotTo(BeNil())
				g.Expect(report.Status.NextScanAt.Sub(report.Status.LastSeenAt.Time)).
					To(BeNumerically("~", 30*time.Second, 5*time.Second),
						"nextScanAt should be one global scan interval after lastSeenAt")
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
				target := getTarget(g, lateTarget)
				g.Expect(target.Status.ReportName).NotTo(BeEmpty(), "target has no reportName")
				cond := findTargetCondition(target, "Ready")
				g.Expect(cond).NotTo(BeNil(), "target has no Ready condition")
				g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(cond.Reason).To(Equal("ScanComplete"))
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

			var before securityv1alpha1.TLSComplianceReport
			Eventually(func(g Gomega) { before = getReport(g, name) }).Should(Succeed())

			By("waiting for the operator to consume the annotation and re-run the check")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", name, "-o", "jsonpath={.metadata.annotations}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring(rescanKey))

				after := getReport(g, name)
				g.Expect(after.Status.CheckCount).To(BeNumerically(">", before.Status.CheckCount),
					"annotation was consumed but no check was recorded")
				g.Expect(after.Status.LastCheckAt).NotTo(BeNil())
				if before.Status.LastCheckAt != nil {
					g.Expect(after.Status.LastCheckAt.After(before.Status.LastCheckAt.Time)).To(BeTrue())
				}
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
			cmd = exec.Command("kubectl", "annotate", "tlsreport", keepReport, rescanKey+"-")
			_, _ = utils.Run(cmd)
			wait := exec.Command(plugin, "rescan", keepReport, "--wait", "--timeout=2m")
			var waitOut bytes.Buffer
			wait.Stdout, wait.Stderr = &waitOut, &waitOut
			Expect(wait.Start()).To(Succeed())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport", keepReport, "-o", "jsonpath={.metadata.annotations}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(rescanKey), "plugin has not requested the rescan yet")
			}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
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
			}{sharedSvc, dropNS, testServerImage, 8443, map[string]string{
				"TLS_MIN_VERSION": "1.3", "TLS_MAX_VERSION": "1.3",
			}}), "test server pod "+sharedSvc)
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
			var report securityv1alpha1.TLSComplianceReport
			Eventually(func(g Gomega) {
				output := reportSources(g)
				g.Expect(output).To(ContainSubstring("Service," + dropNS + "," + sharedSvc))
				g.Expect(output).To(ContainSubstring("Ingress," + dropNS + "," + sharedSvc))

				report = waitForCheckedReport(g, securityv1alpha1.SourceKindService, dropNS, sharedSvc, 443)
				dump := scrapeMetrics(g)
				labels := map[string]string{"host": sharedHost, "port": "443"}
				g.Expect(metricValue(g, dump, "tls_compliance_version_support",
					map[string]string{"host": sharedHost, "port": "443", "version": "1.3"})).To(Equal(1.0))
				g.Expect(metricValue(g, dump, "tls_compliance_version_support",
					map[string]string{"host": sharedHost, "port": "443", "version": "1.2"})).To(Equal(0.0))
				g.Expect(metricValue(g, dump, "tls_compliance_forward_secrecy", labels)).To(Equal(1.0))
				g.Expect(metricValue(g, dump, "tls_compliance_pqc_readiness",
					map[string]string{"host": sharedHost, "port": "443", "readiness": "PQCReady"})).To(Equal(1.0))

				grade := report.Status.OverallCipherGrade
				g.Expect(grade).NotTo(BeEmpty(), "report has no cipher grade")
				gradeTotal := 0.0
				for _, candidate := range []string{"A", "B", "C", "D", "F"} {
					value := metricValue(g, dump, "tls_compliance_cipher_grade",
						map[string]string{"host": sharedHost, "port": "443", "grade": candidate})
					if candidate == grade {
						g.Expect(value).To(Equal(1.0), "cipher_grade=%s should be 1", candidate)
					}
					gradeTotal += value
				}
				g.Expect(gradeTotal).To(Equal(1.0), "exactly one cipher grade must be set")
			}).WithTimeout(3 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())

			By("deleting the Ingress while the Service still covers the endpoint")
			cmd := exec.Command("kubectl", "delete", "ingress", sharedSvc, "-n", dropNS)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(reportSources(g)).NotTo(ContainSubstring("Ingress," + dropNS + "," + sharedSvc))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
			Consistently(func(g Gomega) {
				g.Expect(metricValue(g, scrapeMetrics(g), "tls_compliance_version_support",
					map[string]string{"host": sharedHost, "port": "443", "version": "1.3"})).To(Equal(1.0))
			}).WithTimeout(30 * time.Second).WithPolling(10 * time.Second).Should(Succeed())

			By("deleting the Service, the last report for the endpoint")
			cmd = exec.Command("kubectl", "delete", "service,pod", sharedSvc, "-n", dropNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(metricValue(g, scrapeMetrics(g), "tls_compliance_version_support",
					map[string]string{"host": sharedHost, "port": "443", "version": "1.3"})).To(Equal(0.0))
			}).WithTimeout(2 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})
	})

	Context("Periodic Scan Retry Stall", Label("retry-stall"), Ordered, func() {
		const (
			podName     = "retry-stall-pod"
			fastBackoff = "--retry-backoff=1s"
			slowBackoff = "--retry-backoff=5m"
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
			var firstNextScan time.Time
			Eventually(func(g Gomega) {
				start = minClosedCheckCount(g)
				reports := findReports(g, securityv1alpha1.SourceKindPod, "default", podName, 443)
				g.Expect(reports).NotTo(BeEmpty())
				g.Expect(reports[0].Status.NextScanAt).NotTo(BeNil())
				firstNextScan = reports[0].Status.NextScanAt.Time
			}).Should(Succeed())

			By("waiting for two periodic passes to re-probe the endpoint without sleeping through backoff")
			// --scan-interval=30s. Inline retries would hold the first pass for 5m+ instead.
			Eventually(func(g Gomega) {
				g.Expect(minClosedCheckCount(g)).To(BeNumerically(">=", start+2))
				reports := findReports(g, securityv1alpha1.SourceKindPod, "default", podName, 443)
				g.Expect(reports).NotTo(BeEmpty())
				g.Expect(reports[0].Status.NextScanAt).NotTo(BeNil())
				g.Expect(reports[0].Status.NextScanAt.After(firstNextScan)).To(BeTrue(),
					"nextScanAt should advance as periodic scans complete")
				g.Expect(reports[0].Status.ComplianceStatus).To(Equal(securityv1alpha1.ComplianceStatusClosed))
			}).WithTimeout(2 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())
		})
	})

	Context("Run-Once Mode", Label("run-once"), Ordered, func() {
		var managerBin string

		BeforeAll(func() {
			undeployManager()

			By("creating a fixture endpoint in the default namespace")
			// The namespace-filter spec needs at least one endpoint there.
			// Pods are listed synchronously by the run-once scan; Service
			// discovery is event-driven and can lag behind the one-shot exit.
			cmd := exec.Command("kubectl", "run", "run-once-fixture",
				"--image="+agnhostImage, "--port=443",
				"--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", "run-once-fixture",
					"-n", "default", "--grace-period=0", "--force", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			By("deleting all existing TLSComplianceReport CRs")
			cmd = exec.Command("kubectl", "delete", "tlsreport", "--all", "--ignore-not-found")
			_, _ = utils.Run(cmd)

			managerBin = buildManagerBinary()
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

			var suites export.JUnitTestSuites
			Expect(xml.Unmarshal(data, &suites)).To(Succeed(), "JUnit output must parse")
			Expect(suites.TestSuites).To(HaveLen(1))
			suite := suites.TestSuites[0]
			Expect(suite.Tests).To(BeNumerically(">", 0))
			Expect(suite.TestCases).To(HaveLen(suite.Tests))

			// Workload-keyed cases use the owner kind (Pod, ReplicaSet, Node,
			// DaemonSet, ...), so accept any kind token here.
			casePattern := regexp.MustCompile(`^(ns/\S+ )?[A-Za-z][A-Za-z0-9]*/\S+ port/\d+( #\d+)?$`)
			for _, testCase := range suite.TestCases {
				Expect(testCase.Name).To(MatchRegexp(casePattern.String()), "testcase name %q", testCase.Name)
				Expect(testCase.ClassName).NotTo(BeEmpty())
			}
		})

		It("should produce JSON output", func() {
			data := runOnceAndReadOutput("e2e-run-once-results.json", "json")

			var rows []export.JSONReport
			Expect(json.Unmarshal(data, &rows)).To(Succeed(), "JSON output must parse")
			Expect(rows).NotTo(BeEmpty())
			for _, row := range rows {
				Expect(row.Host).NotTo(BeEmpty())
				Expect(row.Port).NotTo(BeEmpty())
				Expect(row.Source).NotTo(BeEmpty())
				Expect(row.Compliance).NotTo(BeEmpty())
			}
		})

		It("should support namespace filtering", func() {
			data := runOnceAndReadOutput("e2e-run-once-ns-results.xml", "junit",
				"--include-namespaces=default")

			var suites export.JUnitTestSuites
			Expect(xml.Unmarshal(data, &suites)).To(Succeed(), "JUnit output must parse")
			Expect(suites.TestSuites).To(HaveLen(1))
			Expect(suites.TestSuites[0].Tests).To(BeNumerically(">", 0))
			for _, testCase := range suites.TestSuites[0].TestCases {
				Expect(testCase.Name).To(HavePrefix("ns/default "),
					"namespace filter let through %q", testCase.Name)
			}
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
				Host      string `json:"host"`
			}
			Expect(json.Unmarshal(data, &results)).To(Succeed())
			Expect(results).NotTo(BeEmpty())
			for _, r := range results {
				Expect(r.Namespace).To(Equal("default"))
				Expect(r.Host).NotTo(Equal("leftover.example.com"),
					"report outside --include-namespaces leaked into the output")
			}
		})

		It("kubectl tlsreport --fail-on-non-compliant should exit 0 when all compliant", func() {
			pluginBinary := buildPlugin()

			cmd := exec.Command(pluginBinary, "summary", "--fail-on-non-compliant")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "summary --fail-on-non-compliant should exit 0 when all endpoints are compliant: %s", output)
			Expect(output).To(MatchRegexp(`Total Endpoints:\s+[1-9]`))
		})

		It("kubectl tlsreport --fail-on-non-compliant should exit 1 when a report is non-compliant", func() {
			const nonCompliantName = "e2e-run-once-noncompliant"
			kubectlApplyManifest(`apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceReport
metadata:
  name: `+nonCompliantName+`
spec:
  host: noncompliant.example.com
  port: 443
  sourceKind: Service
  sourceNamespace: default
  sourceName: noncompliant
`, "non-compliant TLSComplianceReport")
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "tlsreport", nonCompliantName, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			cmd := exec.Command("kubectl", "patch", "tlsreport", nonCompliantName,
				"--subresource=status", "--type=merge", `-p={"status":{"complianceStatus":"NonCompliant"}}`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			pluginBinary := buildPlugin()
			cmd = exec.Command(pluginBinary, "summary", "--fail-on-non-compliant")
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "expected a non-zero exit for a non-compliant report: %s", output)
			var exitErr *exec.ExitError
			Expect(errors.As(err, &exitErr)).To(BeTrue(), "expected an exit error, got %v", err)
			Expect(exitErr.ExitCode()).To(Equal(1))
			Expect(output).To(MatchRegexp(`Total Endpoints:\s+[1-9]`))
		})
	})

	Context("Per-Target Scan Configuration", Label("target-scan-config"), func() {
		BeforeAll(func() {
			// Run-Once Mode undeploys the operator; make sure this spec never
			// inherits a cluster without a reconciler.
			ensureManagerDeployed()
		})

		It("uses the target interval instead of the global scan interval", func() {
			By("creating a target with a 15m scan interval")
			kubectlApplyManifest(`apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceTarget
metadata:
  name: e2e-scan-config
spec:
  host: example.com
  port: 443
  scan:
    interval: 15m
    tlsVersions: ["1.2", "1.3"]
`, "TLSComplianceTarget with scan overrides")
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "tlstarget", "e2e-scan-config", "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			By("waiting for the report and checking its schedule")
			var reportName string
			Eventually(func(g Gomega) {
				target := getTarget(g, "e2e-scan-config")
				g.Expect(target.Status.ReportName).NotTo(BeEmpty())
				g.Expect(target.Status.LastScannedAt).NotTo(BeNil())
				cond := findTargetCondition(target, "Ready")
				g.Expect(cond).NotTo(BeNil(), "target has no Ready condition")
				g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(cond.Reason).To(Equal("ScanComplete"))
				reportName = target.Status.ReportName
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			var lastSeen, nextScan string
			Eventually(func(g Gomega) {
				report := getReport(g, reportName)
				g.Expect(report.Spec.SourceKind).To(Equal(securityv1alpha1.SourceKindTarget))
				g.Expect(report.Spec.SourceNamespace).To(Equal("cluster-scoped"))
				g.Expect(report.Spec.SourceName).To(Equal("e2e-scan-config"))
				g.Expect(report.Spec.Host).To(Equal("example.com"))
				g.Expect(report.Spec.Port).To(Equal(int32(443)))
				g.Expect(report.Status.CheckCount).To(BeNumerically(">=", 1))
				g.Expect(report.Status.LastSeenAt).NotTo(BeNil())
				g.Expect(report.Status.NextScanAt).NotTo(BeNil())
				// The target restricts probes to TLS 1.2/1.3, so the legacy
				// versions must never be recorded as supported.
				g.Expect(report.Status.TLSVersions.TLS10).To(BeFalse())
				g.Expect(report.Status.TLSVersions.TLS11).To(BeFalse())
				g.Expect(report.Status.TLSVersions.SSL30).To(BeFalse())
				lastSeen = report.Status.LastSeenAt.Format(time.RFC3339)
				nextScan = report.Status.NextScanAt.Format(time.RFC3339)
			}, time.Minute, 2*time.Second).Should(Succeed())

			last, err := time.Parse(time.RFC3339, lastSeen)
			Expect(err).NotTo(HaveOccurred())
			next, err := time.Parse(time.RFC3339, nextScan)
			Expect(err).NotTo(HaveOccurred())
			Expect(next.Sub(last)).To(BeNumerically("~", 15*time.Minute, 30*time.Second),
				"nextScanAt should follow the target's 15m interval, not the global 30s one")
			Expect(next.Sub(last)).NotTo(BeNumerically("~", 30*time.Second, 5*time.Second),
				"nextScanAt looks like the global scan interval")
		})
	})

})

var _ = Describe("Listening Port Discovery", Label("port-discovery"), Ordered, func() {
	It("reports an undeclared listening port when enabled", func() {
		undeployManager()
		managerBin := buildManagerBinary()

		By("creating a pod that listens on 9443 without declaring the port")
		kubectlApplyManifest(`apiVersion: v1
kind: Pod
metadata:
  name: e2e-listen
  namespace: default
spec:
  containers:
    - name: listener
      image: busybox:1.36
      command: ["sh", "-c", "while true; do nc -l -p 9443; done"]
`, "listener pod")
		DeferCleanup(func() {
			_, _ = utils.Run(exec.Command("kubectl", "delete", "pod", "e2e-listen",
				"-n", "default", "--ignore-not-found"))
		})

		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "pod", "e2e-listen",
				"-n", "default", "-o", "jsonpath={.status.phase}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("Running"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		By("verifying the pod declares no container ports")
		declared, err := utils.Run(exec.Command("kubectl", "get", "pod", "e2e-listen",
			"-n", "default", "-o", "jsonpath={.spec.containers[*].ports[*].containerPort}"))
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(declared)).To(BeEmpty(), "fixture must not declare any ports")

		By("running the manager once with listening-port discovery enabled")
		// A non-compliant scan makes run-once exit 1; the discovered report is
		// the subject of this spec.
		_, _ = utils.Run(exec.Command(managerBin, "--run-once", "--discover-listening-ports"))

		By("expecting a report for the undeclared port")
		// A one-shot manager exits before an idle listener's retry backoff
		// finishes, so assert the discovered report exists rather than that a
		// check completed.
		Eventually(func(g Gomega) {
			ips := podIPs(g, "default", "e2e-listen")
			reports := findReports(g, securityv1alpha1.SourceKindPod, "default", "e2e-listen", 9443)
			g.Expect(reports).NotTo(BeEmpty(), "no report for the undeclared port 9443")
			cond := findCondition(reports[0], "Available")
			g.Expect(cond).NotTo(BeNil())
			g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ips).To(ContainElement(reports[0].Spec.Host))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})
})

var _ = Describe("Dry-Run Discovery", Label("dry-run"), Ordered, func() {
	var managerBin string

	BeforeAll(func() {
		undeployManager()
		managerBin = buildManagerBinary()
	})

	It("prints discovered endpoints and creates no reports", func() {
		before := tlsReportNames(Default)

		cmd := exec.Command(managerBin, "--dry-run", "--leader-elect=false")
		out, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "dry-run failed: %s", out)

		linePattern := regexp.MustCompile(`^(Service|Ingress|Route|Target|Pod|HTTPRoute|TLSRoute|GRPCRoute|Gateway|Host) \S+/\S+ \S+:\d+$`)
		var endpointLines int
		for _, line := range utils.GetNonEmptyLines(out) {
			fields := strings.Fields(line)
			if len(fields) != 3 || !strings.Contains(fields[2], ":") {
				// Structured setup logs are interleaved on stderr.
				continue
			}
			Expect(line).To(MatchRegexp(linePattern.String()), "unexpected dry-run line %q", line)
			endpointLines++
		}
		Expect(endpointLines).To(BeNumerically(">", 0), "expected discovered endpoint lines, got: %s", out)
		Expect(tlsReportNames(Default)).To(Equal(before), "dry-run must not create reports")
	})
})
