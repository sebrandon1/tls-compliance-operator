//go:build parity

package parity

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

var scenarios = []Scenario{
	{
		Name:      "TLS 1.3 Only",
		PodName:   "tls13-only",
		Env:       map[string]string{"TLS_MIN_VERSION": "1.3", "TLS_MAX_VERSION": "1.3"},
		Port:      8443,
		ExpectTLS: true,
	},
	{
		Name:      "TLS 1.2 Only",
		PodName:   "tls12-only",
		Env:       map[string]string{"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.2"},
		Port:      8443,
		ExpectTLS: true,
	},
	{
		Name:      "TLS 1.2 and 1.3",
		PodName:   "tls12-13",
		Env:       map[string]string{"TLS_MIN_VERSION": "1.2", "TLS_MAX_VERSION": "1.3"},
		Port:      8443,
		ExpectTLS: true,
	},
	{
		Name:      "Plain HTTP",
		PodName:   "plain-http",
		Env:       map[string]string{"TLS_ENABLED": "false"},
		Port:      8080,
		ExpectTLS: false,
	},
	{
		Name:       "mTLS Required",
		PodName:    "mtls-required",
		Env:        map[string]string{"MTLS_REQUIRED": "true"},
		Port:       8443,
		ExpectTLS:  true,
		ExpectMTLS: true,
	},
}

var _ = Describe("TLS Tool Parity", Ordered, func() {
	var allComparisons []ParityComparison

	BeforeAll(func() {
		createNamespace()
	})

	AfterAll(func() {
		report := generateGapReport(allComparisons)
		writeStepSummary(report)
		deleteNamespace()
	})

	for _, s := range scenarios {
		s := s

		Context(s.Name, Ordered, func() {
			var podIP string
			var operatorResult NormalizedResult
			var scannerResult NormalizedResult

			BeforeAll(func() {
				By("Deploying test pod and service")
				deployTestPod(s)
				createService(s)
				waitForPodReady(s.PodName, 120*time.Second)
				podIP = getPodIP(s.PodName)
				GinkgoWriter.Printf("Pod %s IP: %s\n", s.PodName, podIP)
			})

			AfterAll(func() {
				cleanupScenario(s.PodName)
			})

			It("should be scanned by the operator", func() {
				if !s.ExpectTLS && s.Port != 8443 {
					// Port 8080 is not in the operator's TLS port list — no report expected
					operatorResult = NormalizedResult{
						Endpoint:    fmt.Sprintf("%s:%d", podIP, s.Port),
						Reachable:   true,
						TLSDetected: false,
					}
					GinkgoWriter.Println("Operator does not scan non-TLS ports (expected)")
					return
				}

				reportName := waitForTLSReport(s.PodName, podIP, s.Port, 10*time.Minute)
				GinkgoWriter.Printf("Found TLSComplianceReport: %s\n", reportName)

				// Wait for the report to be checked (not Pending)
				Eventually(func() string {
					out, err := kubectl("get", "tlsreport", reportName,
						"-o", "jsonpath={.status.complianceStatus}")
					if err != nil {
						return "Pending"
					}
					return out
				}).WithTimeout(10 * time.Minute).WithPolling(5 * time.Second).ShouldNot(
					Or(Equal(string(securityv1alpha1.ComplianceStatusPending)),
						Equal(string(securityv1alpha1.ComplianceStatusUnknown)),
						BeEmpty()),
				)

				operatorResult = getOperatorResult(reportName)
				GinkgoWriter.Printf("Operator result: TLS=%v versions=[1.0=%v 1.1=%v 1.2=%v 1.3=%v] mTLS=%v\n",
					operatorResult.TLSDetected,
					operatorResult.TLS10, operatorResult.TLS11,
					operatorResult.TLS12, operatorResult.TLS13,
					operatorResult.MTLSRequired)
			})

			It("should be scanned by the tls-scanner", func() {
				target := fmt.Sprintf("%s:%d", podIP, s.Port)
				By(fmt.Sprintf("Deploying scanner job targeting %s", target))
				deployScannerJob(target)
				waitForScannerJob(3 * time.Minute)

				results := getScannerResults()
				scannerResult = normalizeScannerResult(podIP, s.Port, results)
				GinkgoWriter.Printf("Scanner result: TLS=%v versions=[1.0=%v 1.1=%v 1.2=%v 1.3=%v] mTLS=%v\n",
					scannerResult.TLSDetected,
					scannerResult.TLS10, scannerResult.TLS11,
					scannerResult.TLS12, scannerResult.TLS13,
					scannerResult.MTLSRequired)
			})

			It("should agree on TLS detection", func() {
				Expect(operatorResult.TLSDetected).To(Equal(scannerResult.TLSDetected),
					"TLS detection mismatch for %s", s.Name)
			})

			It("should agree on TLS versions", func() {
				if !s.ExpectTLS {
					Skip("No TLS expected for this scenario")
				}
				if s.ExpectMTLS {
					Skip("mTLS prevents full version enumeration")
				}
				Expect(operatorResult.TLS10).To(Equal(scannerResult.TLS10), "TLS 1.0 mismatch")
				Expect(operatorResult.TLS11).To(Equal(scannerResult.TLS11), "TLS 1.1 mismatch")
				Expect(operatorResult.TLS12).To(Equal(scannerResult.TLS12), "TLS 1.2 mismatch")
				Expect(operatorResult.TLS13).To(Equal(scannerResult.TLS13), "TLS 1.3 mismatch")
			})

			It("should produce a parity comparison", func() {
				comparison := compareResults(s.Name, operatorResult, scannerResult)
				allComparisons = append(allComparisons, comparison)

				if len(comparison.Mismatches) > 0 {
					Fail(fmt.Sprintf("Parity mismatches for %s:\n%s",
						s.Name, strings.Join(comparison.Mismatches, "\n")))
				}
			})
		})
	}
})
