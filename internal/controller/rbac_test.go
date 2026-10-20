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

package controller

import (
	"os"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/sebrandon1/tls-compliance-operator/api/v1alpha1"
)

// TestManagerRoleGrantsTargetFinalizersUpdate guards the generated role: owner
// references with BlockOwnerDeletion are rejected on OpenShift unless the
// controller can update the owner's finalizers subresource.
func TestManagerRoleGrantsTargetFinalizersUpdate(t *testing.T) {
	data, err := os.ReadFile("../../config/rbac/role.yaml")
	if err != nil {
		t.Fatalf("failed to read role.yaml: %v", err)
	}
	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal(data, &role); err != nil {
		t.Fatalf("failed to parse role.yaml: %v", err)
	}
	for _, rule := range role.Rules {
		if slices.Contains(rule.APIGroups, securityv1alpha1.GroupVersion.Group) &&
			slices.Contains(rule.Resources, "tlscompliancetargets/finalizers") &&
			slices.Contains(rule.Verbs, "update") {
			return
		}
	}
	t.Error("manager role must grant update on tlscompliancetargets/finalizers")
}
