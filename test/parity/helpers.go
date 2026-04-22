//go:build parity

package parity

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

const (
	parityNamespace = "parity-test"
	testServerImage = "quay.io/bapalm/tls-test-server:latest"
	scannerImage    = "quay.io/bapalm/tls-scanner:latest"
)

func kubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func kubectlApply(manifest, description string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "%s: %s", description, string(out))
}

func createNamespace() {
	kubectlApply(fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    pod-security.kubernetes.io/enforce: privileged
`, parityNamespace), "create namespace")
}

func deleteNamespace() {
	_, _ = kubectl("delete", "namespace", parityNamespace, "--ignore-not-found", "--timeout=60s")
}

func deployTestPod(s Scenario) {
	envYAML := ""
	for k, v := range s.Env {
		envYAML += fmt.Sprintf(`
    - name: %s
      value: "%s"`, k, v)
	}

	kubectlApply(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    app: %s
    parity-test: "true"
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: server
    image: %s
    env:%s
    ports:
    - containerPort: %d
      name: https
      protocol: TCP
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
`, s.PodName, parityNamespace, s.PodName, testServerImage, envYAML, s.Port),
		fmt.Sprintf("deploy pod %s", s.PodName))
}

func createService(s Scenario) {
	kubectlApply(fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    app: %s
  ports:
  - port: %d
    targetPort: %d
    name: https
`, s.PodName, parityNamespace, s.PodName, s.Port, s.Port),
		fmt.Sprintf("create service %s", s.PodName))
}

func waitForPodReady(podName string, timeout time.Duration) {
	Eventually(func() error {
		_, err := kubectl("wait", "-n", parityNamespace, "--for=condition=Ready",
			fmt.Sprintf("pod/%s", podName), fmt.Sprintf("--timeout=%ds", int(timeout.Seconds())))
		return err
	}).WithTimeout(timeout + 10*time.Second).WithPolling(5 * time.Second).Should(Succeed())
}

func getPodIP(podName string) string {
	ip, err := kubectl("get", "pod", "-n", parityNamespace, podName,
		"-o", "jsonpath={.status.podIP}")
	Expect(err).NotTo(HaveOccurred())
	Expect(ip).NotTo(BeEmpty(), "pod %s has no IP", podName)
	return ip
}

func waitForTLSReport(podIP string, port int, timeout time.Duration) string {
	// CR names use the pattern: <sanitized-ip>-<port>-<hash>
	// The sanitized IP replaces dots with dashes.
	sanitizedIP := strings.ReplaceAll(podIP, ".", "-")
	prefix := fmt.Sprintf("%s-%d-", sanitizedIP, port)

	var reportName string
	Eventually(func() error {
		out, err := kubectl("get", "tlsreport",
			"-o", "jsonpath={.items[*].metadata.name}")
		if err != nil {
			return err
		}
		for _, name := range strings.Fields(out) {
			if strings.HasPrefix(name, prefix) {
				reportName = name
				return nil
			}
		}
		return fmt.Errorf("no TLSComplianceReport found matching prefix %s", prefix)
	}).WithTimeout(timeout).WithPolling(5 * time.Second).Should(Succeed())

	return reportName
}

func getOperatorResult(reportName string) NormalizedResult {
	out, err := kubectl("get", "tlsreport", reportName, "-o", "json")
	Expect(err).NotTo(HaveOccurred())

	var report struct {
		Spec struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"spec"`
		Status struct {
			ComplianceStatus string `json:"complianceStatus"`
			TLSVersions      struct {
				SSL30 bool `json:"ssl30"`
				TLS10 bool `json:"tls10"`
				TLS11 bool `json:"tls11"`
				TLS12 bool `json:"tls12"`
				TLS13 bool `json:"tls13"`
			} `json:"tlsVersions"`
			ForwardSecrecy     bool                `json:"forwardSecrecy"`
			QuantumReady       bool                `json:"quantumReady"`
			OverallCipherGrade string              `json:"overallCipherGrade"`
			KeyExchangeTypes   map[string]string   `json:"keyExchangeTypes"`
			NegotiatedCurves   map[string]string   `json:"negotiatedCurves"`
			CertificateInfo    *struct {
				Issuer          string `json:"issuer"`
				DaysUntilExpiry int    `json:"daysUntilExpiry"`
			} `json:"certificateInfo"`
		} `json:"status"`
	}
	Expect(json.Unmarshal([]byte(out), &report)).To(Succeed())

	s := report.Status
	result := NormalizedResult{
		Endpoint:         fmt.Sprintf("%s:%d", report.Spec.Host, report.Spec.Port),
		Reachable:        !isUnreachable(s.ComplianceStatus),
		TLSDetected:      s.ComplianceStatus != string(securityv1alpha1.ComplianceStatusNoTLS),
		TLS10:            s.TLSVersions.TLS10,
		TLS11:            s.TLSVersions.TLS11,
		TLS12:            s.TLSVersions.TLS12,
		TLS13:            s.TLSVersions.TLS13,
		MTLSRequired:     s.ComplianceStatus == string(securityv1alpha1.ComplianceStatusMutualTLSRequired),
		ForwardSecrecy:   boolPtr(s.ForwardSecrecy),
		PQCReady:         boolPtr(s.QuantumReady),
		CipherGrade:      s.OverallCipherGrade,
		KeyExchangeTypes: s.KeyExchangeTypes,
		NegotiatedCurves: s.NegotiatedCurves,
	}
	if s.CertificateInfo != nil {
		result.CertIssuer = s.CertificateInfo.Issuer
		result.CertDaysToExpiry = &s.CertificateInfo.DaysUntilExpiry
	}
	return result
}

func deployScannerJob(targets string) {
	_, _ = kubectl("delete", "job", "-n", parityNamespace, "parity-tls-scanner", "--ignore-not-found")

	kubectlApply(fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: parity-tls-scanner
  namespace: %s
spec:
  backoffLimit: 0
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: tls-scanner
        image: %s
        imagePullPolicy: IfNotPresent
        args:
        - "--targets"
        - "%s"
        - "--json-file"
        - "/tmp/results.json"
        - "-j"
        - "1"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
      restartPolicy: Never
`, parityNamespace, scannerImage, targets), "deploy scanner job")
}

func waitForScannerJob(timeout time.Duration) {
	_, err := kubectl("wait", "-n", parityNamespace, "--for=condition=complete",
		"job/parity-tls-scanner", fmt.Sprintf("--timeout=%ds", int(timeout.Seconds())))
	Expect(err).NotTo(HaveOccurred(), "scanner job did not complete")
}

func getScannerResults() *ScanResults {
	podName, err := kubectl("get", "pods", "-n", parityNamespace,
		"-l", "job-name=parity-tls-scanner",
		"-o", "jsonpath={.items[0].metadata.name}")
	Expect(err).NotTo(HaveOccurred())

	tmpFile := fmt.Sprintf("/tmp/parity-scanner-results-%d.json", time.Now().UnixNano())
	_, err = kubectl("cp",
		fmt.Sprintf("%s/%s:/tmp/results.json", parityNamespace, podName),
		tmpFile)
	Expect(err).NotTo(HaveOccurred(), "failed to copy results.json from scanner pod")

	data, err := os.ReadFile(tmpFile)
	Expect(err).NotTo(HaveOccurred())
	os.Remove(tmpFile)

	var results ScanResults
	Expect(json.Unmarshal(data, &results)).To(Succeed())
	return &results
}

func normalizeScannerResult(ip string, port int, results *ScanResults) NormalizedResult {
	nr := NormalizedResult{
		Endpoint: fmt.Sprintf("%s:%d", ip, port),
	}

	for _, ipResult := range results.IPResults {
		if ipResult.IP != ip {
			continue
		}

		nr.Reachable = ipResult.Status == "scanned"

		for _, pr := range ipResult.PortResults {
			if pr.Port != port {
				continue
			}

			nr.TLSDetected = pr.Status != "NO_TLS"
			nr.MTLSRequired = strings.Contains(strings.ToLower(pr.Reason), "mutual") ||
				strings.Contains(strings.ToLower(pr.Reason), "client cert")

			for _, v := range pr.TlsVersions {
				switch v {
				case "TLSv1.0":
					nr.TLS10 = true
				case "TLSv1.1":
					nr.TLS11 = true
				case "TLSv1.2":
					nr.TLS12 = true
				case "TLSv1.3":
					nr.TLS13 = true
				}
			}

			nr.CipherSuites = pr.TlsCiphers
			nr.MLKEMSupported = boolPtr(pr.MLKEMSupported)

			return nr
		}
	}

	return nr
}

func compareResults(scenario string, operator, scanner NormalizedResult) ParityComparison {
	c := ParityComparison{Scenario: scenario}

	checkBool := func(name string, op, sc bool) {
		if op == sc {
			c.Matches = append(c.Matches, name)
		} else {
			c.Mismatches = append(c.Mismatches,
				fmt.Sprintf("%s: operator=%v scanner=%v", name, op, sc))
		}
	}

	checkBool("TLS Detected", operator.TLSDetected, scanner.TLSDetected)
	checkBool("TLS 1.0", operator.TLS10, scanner.TLS10)
	checkBool("TLS 1.1", operator.TLS11, scanner.TLS11)
	checkBool("TLS 1.2", operator.TLS12, scanner.TLS12)
	checkBool("TLS 1.3", operator.TLS13, scanner.TLS13)

	if operator.ForwardSecrecy != nil {
		c.OperatorOnly = append(c.OperatorOnly, fmt.Sprintf("ForwardSecrecy=%v", *operator.ForwardSecrecy))
	}
	if operator.PQCReady != nil {
		c.OperatorOnly = append(c.OperatorOnly, fmt.Sprintf("PQCReady=%v", *operator.PQCReady))
	}
	if operator.CipherGrade != "" {
		c.OperatorOnly = append(c.OperatorOnly, fmt.Sprintf("CipherGrade=%s", operator.CipherGrade))
	}
	if len(operator.KeyExchangeTypes) > 0 {
		c.OperatorOnly = append(c.OperatorOnly, fmt.Sprintf("KeyExchangeTypes=%v", operator.KeyExchangeTypes))
	}
	if len(operator.NegotiatedCurves) > 0 {
		c.OperatorOnly = append(c.OperatorOnly, fmt.Sprintf("NegotiatedCurves=%v", operator.NegotiatedCurves))
	}
	if operator.CertIssuer != "" {
		c.OperatorOnly = append(c.OperatorOnly, fmt.Sprintf("CertIssuer=%s", operator.CertIssuer))
	}

	if len(scanner.CipherSuites) > 0 {
		c.ScannerOnly = append(c.ScannerOnly, fmt.Sprintf("CipherSuites=%v", scanner.CipherSuites))
	}
	if scanner.MLKEMSupported != nil {
		c.ScannerOnly = append(c.ScannerOnly, fmt.Sprintf("MLKEMSupported=%v", *scanner.MLKEMSupported))
	}

	return c
}

func generateGapReport(comparisons []ParityComparison) string {
	var sb strings.Builder

	sb.WriteString("## TLS Parity Gap Report\n\n")
	sb.WriteString("### Comparison Summary\n")
	sb.WriteString("| Scenario | Overlapping Fields | Matches | Mismatches |\n")
	sb.WriteString("|---|---|---|---|\n")

	for _, c := range comparisons {
		total := len(c.Matches) + len(c.Mismatches)
		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d |\n",
			c.Scenario, total, len(c.Matches), len(c.Mismatches)))
	}

	hasMismatches := false
	for _, c := range comparisons {
		if len(c.Mismatches) > 0 {
			hasMismatches = true
			break
		}
	}
	if hasMismatches {
		sb.WriteString("\n### Mismatches (Failures)\n")
		sb.WriteString("| Scenario | Mismatch |\n")
		sb.WriteString("|---|---|\n")
		for _, c := range comparisons {
			for _, m := range c.Mismatches {
				sb.WriteString(fmt.Sprintf("| %s | %s |\n", c.Scenario, m))
			}
		}
	}

	sb.WriteString("\n### Non-Overlapping Fields (Gaps)\n")
	sb.WriteString("| Scenario | Source | Fields |\n")
	sb.WriteString("|---|---|---|\n")
	for _, c := range comparisons {
		if len(c.OperatorOnly) > 0 {
			sb.WriteString(fmt.Sprintf("| %s | Operator only | %s |\n",
				c.Scenario, strings.Join(c.OperatorOnly, ", ")))
		}
		if len(c.ScannerOnly) > 0 {
			sb.WriteString(fmt.Sprintf("| %s | Scanner only | %s |\n",
				c.Scenario, strings.Join(c.ScannerOnly, ", ")))
		}
	}

	return sb.String()
}

func writeStepSummary(report string) {
	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryPath != "" {
		_ = os.WriteFile(summaryPath, []byte(report), 0o644)
	}
	GinkgoWriter.Println(report)
}

func cleanupScenario(podName string) {
	_, _ = kubectl("delete", "pod", "-n", parityNamespace, podName, "--ignore-not-found", "--grace-period=0", "--force")
	_, _ = kubectl("delete", "svc", "-n", parityNamespace, podName, "--ignore-not-found")
	_, _ = kubectl("delete", "job", "-n", parityNamespace, "parity-tls-scanner", "--ignore-not-found")
}

func isUnreachable(status string) bool {
	switch status {
	case string(securityv1alpha1.ComplianceStatusUnreachable),
		string(securityv1alpha1.ComplianceStatusTimeout),
		string(securityv1alpha1.ComplianceStatusClosed),
		string(securityv1alpha1.ComplianceStatusFiltered):
		return true
	}
	return false
}

func boolPtr(b bool) *bool {
	return &b
}
