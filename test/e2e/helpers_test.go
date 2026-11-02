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

	. "github.com/onsi/gomega"

	"github.com/sebrandon1/tls-compliance-operator/test/utils"
)

// managerDeployment is the operator Deployment that the e2e suites patch.
const managerDeployment = "tls-compliance-operator-controller-manager"

// addManagerArg appends arg to the manager container and waits for the rollout.
func addManagerArg(arg string) {
	patch := fmt.Sprintf(`[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":%q}]`, arg)
	cmd := exec.Command("kubectl", "patch", "deployment",
		managerDeployment, "-n", namespace, "--type=json", "-p="+patch)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to add manager arg %s", arg)
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
