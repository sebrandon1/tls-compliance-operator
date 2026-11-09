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

package policy

import (
	"strings"
	"testing"
)

func mustCompile(t *testing.T, doc string) *CompileResult {
	t.Helper()
	result, err := Compile([]byte(doc))
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return result
}

func TestPolicy_FirstMatchWins(t *testing.T) {
	result := mustCompile(t, `
rules:
  - namespace: "^openshift-ingress$"
    profile: ingress
  - port: "^10250$"
    profile: kubelet
  - namespace: "^openshift-e2e-loki$"
    profile: exempt
`)
	p := result.Policy

	tests := []struct {
		name   string
		target Target
		want   Profile
	}{
		{name: "ingress namespace", target: Target{Namespace: "openshift-ingress", Port: 8443}, want: ProfileIngress},
		{name: "kubelet port", target: Target{Namespace: "other", Port: 10250}, want: ProfileKubelet},
		{name: "exempt namespace", target: Target{Namespace: "openshift-e2e-loki", Port: 443}, want: ProfileExempt},
		{name: "default fallback", target: Target{Namespace: "default", Port: 443}, want: DefaultProfile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Match(tt.target); got != tt.want {
				t.Errorf("Match(%+v) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestPolicy_MatchersAreAnchored(t *testing.T) {
	p := mustCompile(t, `
rules:
  - namespace: "openshift-ingress"
    profile: ingress
`).Policy

	if got := p.Match(Target{Namespace: "not-openshift-ingress-x"}); got != DefaultProfile {
		t.Errorf("Match() = %q, want default for a substring-only match", got)
	}
	if got := p.Match(Target{Namespace: "openshift-ingress"}); got != ProfileIngress {
		t.Errorf("Match() = %q, want ingress", got)
	}
}

func TestPolicy_CatchAllAppliesLast(t *testing.T) {
	p := mustCompile(t, `
rules:
  - namespace: "^kube-system$"
    profile: kubelet
  - profile: apiserver
`).Policy

	if got := p.Match(Target{Namespace: "kube-system"}); got != ProfileKubelet {
		t.Errorf("Match(kube-system) = %q, want kubelet", got)
	}
	if got := p.Match(Target{Namespace: "default"}); got != ProfileAPIServer {
		t.Errorf("Match(default) = %q, want apiserver", got)
	}
}

func TestCompile_RejectsInvalidRegex(t *testing.T) {
	if _, err := Compile([]byte(`
rules:
  - namespace: "[unterminated"
    profile: apiserver
`)); err == nil {
		t.Fatal("Compile() error = nil, want an error for an invalid regex")
	}
}

func TestCompile_RejectsUnknownProfile(t *testing.T) {
	if _, err := Compile([]byte(`
rules:
  - namespace: "foo"
    profile: bogus
`)); err == nil {
		t.Fatal("Compile() error = nil, want an error for an unknown profile")
	}
}

func TestCompile_WarnsOnShadowedRules(t *testing.T) {
	result := mustCompile(t, `
rules:
  - profile: apiserver
  - namespace: "^shadowed$"
    profile: ingress
  - namespace: "^dup$"
    profile: ingress
  - namespace: "^dup$"
    profile: exempt
`)
	if len(result.Warnings) == 0 {
		t.Fatal("Compile() warnings = none, want shadow warnings")
	}
	joined := strings.Join(result.Warnings, "\n")
	if !strings.Contains(joined, "catch-all") {
		t.Errorf("warnings = %q, want a catch-all shadow warning", joined)
	}
	if !strings.Contains(joined, "duplicates") {
		t.Errorf("warnings = %q, want a duplicate-rule warning", joined)
	}
}

func TestPolicy_NilDefaultsToAPIServer(t *testing.T) {
	var p *Policy
	if got := p.Match(Target{Namespace: "default"}); got != ProfileAPIServer {
		t.Errorf("nil Policy Match() = %q, want apiserver", got)
	}
}

func TestPolicy_ProcessAndComponentMatchers(t *testing.T) {
	p := mustCompile(t, `
rules:
  - process: "^oauth-proxy$"
    component: "^Pod$"
    profile: exempt
`).Policy

	if got := p.Match(Target{Process: "oauth-proxy", Component: "Pod"}); got != ProfileExempt {
		t.Errorf("Match() = %q, want exempt", got)
	}
	if got := p.Match(Target{Process: "oauth-proxy", Component: "Service"}); got != DefaultProfile {
		t.Errorf("Match() = %q, want default when the component differs", got)
	}
}
