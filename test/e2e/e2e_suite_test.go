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
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var managerImage = os.Getenv("IMG")

func TestE2E(t *testing.T) {
	if managerImage == "" {
		// Build the manager image if not specified
		managerImage = "tls-compliance-operator:test-e2e"

		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", managerImage))
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build manager image: %v\nOutput: %s", err, output)
		}

		// Load the image into Kind cluster
		kindCluster := os.Getenv("KIND_CLUSTER")
		if kindCluster == "" {
			kindCluster = "tls-compliance-operator-test-e2e"
		}
		kindBin := os.Getenv("KIND")
		if kindBin == "" {
			kindBin = "kind"
		}
		cmd = exec.Command(kindBin, "load", "docker-image", managerImage, "--name", kindCluster)
		output, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to load image into Kind: %v\nOutput: %s", err, output)
		}
	}

	RegisterFailHandler(Fail)
	RunSpecs(t, "E2E Suite")
}
