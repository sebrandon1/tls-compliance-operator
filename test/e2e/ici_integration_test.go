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
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sebrandon1/tls-compliance-operator/test/utils"
)

const (
	iciNamespace  = "imagecertinfo-operator-system"
	iciViewerRole = "imagecertinfo-operator-imagecertificationinfo-viewer-role"
)

var _ = Describe("ICI Integration", Label("ici-integration"), Ordered, func() {
	var iciRepo string

	BeforeAll(func() {
		iciRepo = os.Getenv("ICI_REPO")
		if iciRepo == "" {
			Skip("ICI_REPO not set — skipping ICI integration tests")
		}

		iciImg := os.Getenv("ICI_IMG")
		if iciImg == "" {
			iciImg = "imagecertinfo-operator:test"
		}

		kindCluster := os.Getenv("KIND_CLUSTER")
		if kindCluster == "" {
			kindCluster = "tls-compliance-operator-test-e2e"
		}
		kindBin := os.Getenv("KIND")
		if kindBin == "" {
			kindBin = "kind"
		}

		By("building imagecertinfo-operator image")
		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", iciImg))
		cmd.Dir = iciRepo
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to build ICI operator image")

		By("loading imagecertinfo-operator image into Kind")
		cmd = exec.Command(kindBin, "load", "docker-image", iciImg, "--name", kindCluster)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to load ICI image into Kind")

		By("creating ICI operator namespace")
		cmd = exec.Command("kubectl", "create", "ns", iciNamespace)
		_, _ = utils.Run(cmd) // ignore if already exists

		By("installing ICI CRDs")
		cmd = exec.Command("make", "install")
		cmd.Dir = iciRepo
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install ICI CRDs")

		By("deploying imagecertinfo-operator")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", iciImg))
		cmd.Dir = iciRepo
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy imagecertinfo-operator")

		By("waiting for imagecertinfo-operator to be ready")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "deployment",
				"imagecertinfo-operator-controller-manager",
				"-n", iciNamespace,
				"-o", "jsonpath={.status.availableReplicas}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(output)).To(Equal("1"))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("granting tls-compliance-operator SA permission to list ICI CRs")
		cmd = exec.Command("kubectl", "create", "clusterrolebinding",
			"imagecertinfo-viewer-for-tls-operator",
			fmt.Sprintf("--clusterrole=%s", iciViewerRole),
			fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName))
		_, _ = utils.Run(cmd) // ignore if already exists
	})

	AfterAll(func() {
		if iciRepo == "" {
			return
		}

		By("removing ICI viewer RBAC binding")
		cmd := exec.Command("kubectl", "delete", "clusterrolebinding",
			"imagecertinfo-viewer-for-tls-operator", "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("undeploying imagecertinfo-operator")
		cmd = exec.Command("make", "undeploy")
		cmd.Dir = iciRepo
		_, _ = utils.Run(cmd)

		By("uninstalling ICI CRDs")
		cmd = exec.Command("make", "uninstall")
		cmd.Dir = iciRepo
		_, _ = utils.Run(cmd)

		By("removing ICI namespace")
		cmd = exec.Command("kubectl", "delete", "ns", iciNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	Context("Pod source with ICI installed", Ordered, func() {
		const iciTestPodName = "ici-integ-test-pod"

		BeforeAll(func() {
			By("deploying a test pod for ICI enrichment")
			cmd := exec.Command("kubectl", "run", iciTestPodName,
				"--image=registry.access.redhat.com/ubi9/ubi-minimal:latest",
				"--port=443", "--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pod", iciTestPodName,
				"--grace-period=0", "--force", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create an ImageCertificationInfo CR with a digest label", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "imagecertificationinfoes",
					"-o", "jsonpath={range .items[*]}{.metadata.labels.imagecertinfo\\.security\\.telco\\.openshift\\.io/digest}{'\\n'}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				labels := utils.GetNonEmptyLines(output)
				g.Expect(labels).NotTo(BeEmpty(), "no ICI CRs with digest labels found")
				for _, lbl := range labels {
					g.Expect(lbl).To(HavePrefix("sha256-"))
				}
			}, 5*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should populate imageCertificationInfo on the Pod TLSComplianceReport", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", fmt.Sprintf(
						"jsonpath={range .items[?(@.spec.sourceName==%q)]}{.status.imageCertificationInfo}{'\\n'}{end}",
						iciTestPodName))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).NotTo(BeEmpty(),
					"imageCertificationInfo should be populated for Pod %s", iciTestPodName)
			}, 5*time.Minute, 10*time.Second).Should(Succeed())
		})
	})

	Context("Pod source with ICI not installed", Ordered, func() {
		const gracefulTestPodName = "ici-graceful-test-pod"

		BeforeAll(func() {
			By("undeploying imagecertinfo-operator to test graceful degradation")
			cmd := exec.Command("make", "undeploy")
			cmd.Dir = iciRepo
			_, _ = utils.Run(cmd)

			By("uninstalling ICI CRDs")
			cmd = exec.Command("make", "uninstall")
			cmd.Dir = iciRepo
			_, _ = utils.Run(cmd)

			By("deploying a test pod after ICI removal")
			cmd = exec.Command("kubectl", "run", gracefulTestPodName,
				"--image=registry.access.redhat.com/ubi9/ubi-minimal:latest",
				"--port=443", "--command", "--", "sleep", "3600")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "pod", gracefulTestPodName,
				"--grace-period=0", "--force", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create a TLSComplianceReport without imageCertificationInfo", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "tlsreport",
					"-o", fmt.Sprintf(
						"jsonpath={range .items[?(@.spec.sourceName==%q)]}{.status.imageCertificationInfo}{'\\n'}{end}",
						gracefulTestPodName))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
					"imageCertificationInfo should be absent when ICI CRD not installed")
			}, 5*time.Minute, 10*time.Second).Should(Succeed())
		})
	})
})
