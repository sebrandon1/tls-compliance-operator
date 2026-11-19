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

// Package policy maps discovered TLS endpoints to the component profile they
// should be evaluated against, and marks endpoints that are exempt from profile
// adherence.
package policy

import (
	"fmt"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Profile names a policy rule can select. ProfileExempt marks an endpoint as
// exempt from profile adherence; it is still scanned and reported.
type Profile string

const (
	ProfileAPIServer Profile = "apiserver"
	ProfileIngress   Profile = "ingress"
	ProfileKubelet   Profile = "kubelet"
	ProfileExempt    Profile = "exempt"
)

// DefaultProfile is applied when no rule matches.
const DefaultProfile = ProfileAPIServer

// Document is the YAML shape of the policy ConfigMap.
type Document struct {
	Rules []RuleSpec `yaml:"rules"`
}

// RuleSpec is a single policy rule as written in the ConfigMap.
type RuleSpec struct {
	// Namespace matches the source object's namespace.
	Namespace string `yaml:"namespace,omitempty"`
	// Process matches the source object name (for pods, the workload owner).
	Process string `yaml:"process,omitempty"`
	// Port matches the endpoint port as a decimal string.
	Port string `yaml:"port,omitempty"`
	// Component matches the source kind (Service, Pod, Ingress, Route, ...).
	Component string `yaml:"component,omitempty"`
	// Profile is one of apiserver, ingress, kubelet, or exempt.
	Profile string `yaml:"profile"`
	// Reason is a human explanation of the rule, surfaced as the exemption
	// reason on exempt endpoints.
	Reason string `yaml:"reason,omitempty"`
	// NotAfter is when the rule stops applying: either an RFC3339 timestamp or
	// a YYYY-MM-DD date, which expires at the end of that day in UTC. Empty
	// means the rule never expires.
	NotAfter string `yaml:"notAfter,omitempty"`
}

// Rule is a compiled policy rule.
type Rule struct {
	namespace *regexp.Regexp
	process   *regexp.Regexp
	port      *regexp.Regexp
	component *regexp.Regexp
	Profile   Profile
	// notAfter is when the rule stops applying; zero means it never does.
	notAfter time.Time
	// Spec keeps the original text for messages.
	Spec RuleSpec
}

// Target is the endpoint data a rule is matched against.
type Target struct {
	Namespace string
	Process   string
	Port      int32
	Component string
}

// Policy is a compiled, ordered rule set evaluated first-match-wins.
type Policy struct {
	rules []Rule
}

// CompileResult carries the compiled policy plus non-fatal warnings, such as
// rules that can never match because an earlier rule shadows them.
type CompileResult struct {
	Policy   *Policy
	Warnings []string
}

// Compile parses and validates a policy document.
func Compile(data []byte) (*CompileResult, error) {
	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	result := &CompileResult{Policy: &Policy{}}
	catchAllBefore := -1
	seen := make(map[string]int)
	for i := range doc.Rules {
		spec := &doc.Rules[i]
		rule, err := compileRule(spec)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if catchAllBefore >= 0 {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("rule %d can never match: rule %d is a catch-all", i, catchAllBefore))
		}
		if key := ruleKey(spec); key != "" {
			if first, ok := seen[key]; ok {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("rule %d duplicates rule %d and can never match", i, first))
			} else {
				seen[key] = i
			}
		}
		if isCatchAll(spec) && catchAllBefore < 0 {
			catchAllBefore = i
		}
		result.Policy.rules = append(result.Policy.rules, rule)
	}
	return result, nil
}

// compileRule validates and compiles one rule.
func compileRule(spec *RuleSpec) (Rule, error) {
	profile := Profile(spec.Profile)
	switch profile {
	case ProfileAPIServer, ProfileIngress, ProfileKubelet, ProfileExempt:
	default:
		return Rule{}, fmt.Errorf("unknown profile %q (want apiserver, ingress, kubelet, or exempt)", spec.Profile)
	}

	rule := Rule{Profile: profile, Spec: *spec}
	notAfter, err := parseNotAfter(spec.NotAfter)
	if err != nil {
		return Rule{}, err
	}
	rule.notAfter = notAfter
	if rule.namespace, err = compileMatcher(spec.Namespace); err != nil {
		return Rule{}, fmt.Errorf("namespace: %w", err)
	}
	if rule.process, err = compileMatcher(spec.Process); err != nil {
		return Rule{}, fmt.Errorf("process: %w", err)
	}
	if rule.port, err = compileMatcher(spec.Port); err != nil {
		return Rule{}, fmt.Errorf("port: %w", err)
	}
	if rule.component, err = compileMatcher(spec.Component); err != nil {
		return Rule{}, fmt.Errorf("component: %w", err)
	}
	return rule, nil
}

// parseNotAfter parses a rule expiry. A date-only value expires at the end of
// that day in UTC, so the same rule behaves identically in every timezone.
func parseNotAfter(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts, nil
	}
	if day, err := time.Parse("2006-01-02", value); err == nil {
		return day.Add(24 * time.Hour), nil
	}
	return time.Time{}, fmt.Errorf("invalid notAfter %q (want RFC3339 or YYYY-MM-DD)", value)
}

// activeAt reports whether the rule still applies at now.
func (r *Rule) activeAt(now time.Time) bool {
	return r.notAfter.IsZero() || now.Before(r.notAfter)
}

// compileMatcher anchors a rule expression. An empty expression matches
// everything.
func compileMatcher(expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	return regexp.Compile("^(?:" + expr + ")$")
}

// isCatchAll reports whether spec matches every target.
func isCatchAll(spec *RuleSpec) bool {
	return spec.Namespace == "" && spec.Process == "" && spec.Port == "" && spec.Component == ""
}

// ruleKey identifies rules with identical matchers.
func ruleKey(spec *RuleSpec) string {
	if isCatchAll(spec) {
		return ""
	}
	// notAfter is part of the key: two rules with the same matchers but
	// different expiry are not duplicates.
	return spec.Namespace + "\x00" + spec.Process + "\x00" + spec.Port + "\x00" + spec.Component +
		"\x00" + spec.NotAfter
}

// Match returns the profile selected for target at the current time, using
// first-match-wins ordering and DefaultProfile when nothing matches.
func (p *Policy) Match(target Target) Profile {
	profile, _ := p.MatchAt(target, time.Now())
	return profile
}

// MatchDetailed returns the profile selected for target at the current time
// and the index of the matching rule, or -1 when no rule matched.
func (p *Policy) MatchDetailed(target Target) (Profile, int) {
	return p.MatchAt(target, time.Now())
}

// MatchAt returns the profile selected for target at now and the index of the
// matching rule, or -1 when no rule matched. An expired rule does not match,
// so later rules and the default still apply.
func (p *Policy) MatchAt(target Target, now time.Time) (Profile, int) {
	if p == nil {
		return DefaultProfile, -1
	}
	for i := range p.rules {
		if p.rules[i].activeAt(now) && p.rules[i].matches(target) {
			return p.rules[i].Profile, i
		}
	}
	return DefaultProfile, -1
}

// SpecAt returns the original spec of the rule at index.
func (p *Policy) SpecAt(index int) (RuleSpec, bool) {
	if p == nil || index < 0 || index >= len(p.rules) {
		return RuleSpec{}, false
	}
	return p.rules[index].Spec, true
}

// matches reports whether every configured matcher accepts target.
func (r *Rule) matches(target Target) bool {
	return matchOrEmpty(r.namespace, target.Namespace) &&
		matchOrEmpty(r.process, target.Process) &&
		matchOrEmpty(r.port, fmt.Sprintf("%d", target.Port)) &&
		matchOrEmpty(r.component, target.Component)
}

// matchOrEmpty applies re when set and accepts anything when it is nil.
func matchOrEmpty(re *regexp.Regexp, value string) bool {
	return re == nil || re.MatchString(value)
}
