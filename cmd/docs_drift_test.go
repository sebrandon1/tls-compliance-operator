package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envlessFlags are operator flags that deliberately have no TLS_COMPLIANCE_*
// environment variable. They are the kubebuilder scaffolding knobs, documented
// in the "Infrastructure" table of docs/configuration.md, which has no Env Var
// column. Do not add an entry just to silence this test: a user-facing flag
// should get an env mapping and a docs row instead.
var envlessFlags = map[string]string{
	"metrics-bind-address":      "scaffolding: set from the manager Deployment args",
	"health-probe-bind-address": "scaffolding: set from the manager Deployment args",
	"leader-elect":              "scaffolding: enabled by the kustomize HA overlay",
	"metrics-secure":            "scaffolding: metrics TLS is a deployment concern",
	"enable-http2":              "scaffolding: transport hardening knob, not lab config",
	"metrics-cert-path":         "scaffolding: metrics server TLS material",
	"metrics-cert-name":         "scaffolding: metrics server TLS material",
	"metrics-cert-key":          "scaffolding: metrics server TLS material",
	"webhook-cert-path":         "scaffolding: webhook server TLS material",
	"webhook-cert-name":         "scaffolding: webhook server TLS material",
	"webhook-cert-key":          "scaffolding: webhook server TLS material",
}

// TestOperatorFlagEnvDocsDrift keeps the three places that describe operator
// configuration in sync: the flags registered by registerOperatorFlags, the
// envFlagMapping env-var table, and the table in docs/configuration.md.
//
// To add a flag: register it in registerOperatorFlags, add it to
// envFlagMapping, and add a row to docs/configuration.md. If it is genuinely
// CLI-only, add it to envlessFlags with a reason.
func TestOperatorFlagEnvDocsDrift(t *testing.T) {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	cfg := &operatorConfig{}
	registerOperatorFlags(fs, cfg)

	registered := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { registered[f.Name] = true })

	if len(registered) == 0 {
		t.Fatal("registerOperatorFlags registered no flags")
	}

	mapped := map[string]string{}
	for _, m := range envFlagMapping {
		if prev, dup := mapped[m.flagName]; dup {
			t.Errorf("envFlagMapping lists flag %q twice (%s and %s)", m.flagName, prev, m.envVar)
		}
		mapped[m.flagName] = m.envVar

		if !registered[m.flagName] {
			t.Errorf("envFlagMapping: flag %q is not registered by registerOperatorFlags", m.flagName)
		}
		if !strings.HasPrefix(m.envVar, "TLS_COMPLIANCE_") {
			t.Errorf("envFlagMapping: env var %q for flag %q must start with TLS_COMPLIANCE_", m.envVar, m.flagName)
		}
	}

	for name := range registered {
		_, envless := envlessFlags[name]
		_, hasEnv := mapped[name]
		switch {
		case envless && hasEnv:
			t.Errorf("flag %q is in envlessFlags but also has env mapping %s; remove one", name, mapped[name])
		case !envless && !hasEnv:
			t.Errorf("flag %q has no env mapping in envFlagMapping and is not in envlessFlags with a reason", name)
		}
	}
	for name, reason := range envlessFlags {
		if !registered[name] {
			t.Errorf("envlessFlags lists %q, but registerOperatorFlags no longer registers it", name)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("envlessFlags entry %q has no reason; every exception needs one", name)
		}
	}

	docBytes, err := os.ReadFile(filepath.Join("..", "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("read docs/configuration.md: %v", err)
	}
	docs := string(docBytes)

	for name := range registered {
		if !strings.Contains(docs, "`--"+name+"`") {
			t.Errorf("flag %q has no `--%s` row in docs/configuration.md", name, name)
		}
	}
	for flagName, envVar := range mapped {
		if !strings.Contains(docs, envVar) {
			t.Errorf("env var %s (flag %q) is not mentioned in docs/configuration.md", envVar, flagName)
		}
	}
}
