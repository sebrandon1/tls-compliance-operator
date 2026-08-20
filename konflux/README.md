# Konflux onboarding and reusable TLS compliance scan pipeline

This directory holds Konflux resources for:

1. **Onboarding `tls-compliance-operator` itself** so Konflux builds the image
   and can run integration checks on PRs to this repo.
2. **Publishing a reusable compliance-scan Pipeline** that layered products can
   point at from their own `IntegrationTestScenario` (via Tekton git resolver)
   to scan their ephemeral test environments for TLS and PQC/ML-KEM compliance.

## Important: what is and is not auto-applied from git

**None of the `Application` / `Component` / `IntegrationTestScenario` CRs are
watched or auto-applied by Konflux.** Someone with `oc`/`kubectl` access to the
Konflux tenant namespace must apply them explicitly.

Only Pipeline / PipelineRun YAML referenced by an already-applied ITS
`resolverRef` (or by Pipelines-as-Code `.tekton/*.yaml` files) is fetched from
git at run time.

## Layout

| File | Applied to cluster? | Purpose |
|---|---|---|
| [`application.yaml`](application.yaml) | Yes | Konflux `Application` for this component. |
| [`component.yaml`](component.yaml) | Yes | `Component` + `ImageRepository`. Triggers Konflux's PaC bot to open a *separate* onboarding PR with generated `.tekton/` build PipelineRuns. Uses the existing `Dockerfile` (public `golang` + `distroless` bases). |
| [`integration-test-scenario.yaml`](integration-test-scenario.yaml) | Yes | ITS CRs for this repo's own self-test and smoke checks. |
| [`pipelines/tls-compliance-smoke-test.yaml`](pipelines/tls-compliance-smoke-test.yaml) | No (git-resolved) | Light check: `manager --help` on the Snapshot image. |
| [`pipelines/tls-compliance-self-test.yaml`](pipelines/tls-compliance-self-test.yaml) | No (git-resolved) | End-to-end self-test: smoke + TLS fixture pod + run-once scan in the PipelineRun namespace. |
| [`pipelines/tls-compliance-scan.yaml`](pipelines/tls-compliance-scan.yaml) | No (git-resolved) | **Reusable pipeline for layered products.** Deploys a run-once scan Job into a target cluster identified by a kubeconfig Secret. |

## Prerequisites

This repo's Konflux tenant namespace is **`ocp-isc-tenant`**. Manifests under
`konflux/*.yaml` already use that value.

Also required:

- Konflux GitHub App installed on the `sebrandon1` org (or at least this repo).
- Push access for branches matching `konflux-*` (PaC onboarding / MintMaker).

## Onboarding tls-compliance-operator (apply order)

1. `oc apply -f konflux/application.yaml` (namespace: `ocp-isc-tenant`)
2. `oc apply -f konflux/component.yaml` — Konflux opens a separate PaC PR with
   generated `.tekton/*.yaml` build pipelines. Review and merge **that** PR
   before expecting builds.
3. After a build Snapshot exists: `oc apply -f konflux/integration-test-scenario.yaml`

### Validating pipelines from a feature PR

1. Temporarily set each ITS `resolverRef` `revision` param to your branch name
   (e.g. `feat/konflux-tls-scan`).
2. Re-apply the ITS: `oc apply -f konflux/integration-test-scenario.yaml`
3. Open/update the GitHub PR — Konflux posts integration checks (e.g.
   `tls-compliance-operator-self-test`). Click **Details** to open the Tekton UI.
4. Because the ITS carries `test.appstudio.openshift.io/optional: "true"`, a
   failing check will not block the Snapshot while bootstrapping.
5. Flip `revision` back to `main`, re-apply, and merge the PR.

## Using tls-compliance-operator from a layered product

The operator scans TLS endpoints via the Kubernetes API (Services, Ingresses,
Routes, Pods) and makes outbound TCP connections to check TLS versions and
ML-KEM support. It does **not** need privileged SCC or pods/exec access — only
standard read access to cluster resources plus its own CRDs.

Layered products that already provision an ephemeral test environment for their
Snapshot should:

1. Store a kubeconfig for that environment in a Secret in their Konflux tenant
   namespace (key defaults to `kubeconfig`).
2. Apply an `IntegrationTestScenario` in **their** tenant that points at this
   repo's compliance pipeline:

```yaml
apiVersion: appstudio.redhat.com/v1beta2
kind: IntegrationTestScenario
metadata:
  name: tls-compliance-scan
  namespace: <YOUR_TENANT_NAMESPACE>
  labels:
    test.appstudio.openshift.io/optional: "true"
spec:
  application: <YOUR_APPLICATION_NAME>
  contexts:
    - description: TLS/PQC compliance scan of the ephemeral test environment
      name: application
  resolverRef:
    resolver: git
    params:
      - name: url
        value: https://github.com/sebrandon1/tls-compliance-operator.git
      # Pin to a tag or known-good commit.
      - name: revision
        value: main
      - name: pathInRepo
        value: konflux/pipelines/tls-compliance-scan.yaml
  params:
    - name: TARGET_KUBECONFIG_SECRET
      value: <secret-name-holding-target-kubeconfig>
    # Optional overrides:
    # - name: TARGET_KUBECONFIG_SECRET_KEY
    #   value: kubeconfig
    # - name: SCANNER_IMAGE
    #   value: quay.io/<org>/tls-compliance-operator:<released-tag>
    # - name: INCLUDE_NAMESPACES
    #   value: my-product-ns
    # - name: EXCLUDE_NAMESPACES
    #   value: kube-system,openshift-monitoring
    # - name: OUTPUT_FORMAT
    #   value: junit
    # - name: SCAN_NAMESPACE
    #   value: tls-compliance-operator
```

### Compliance pipeline parameters

| Param | Required | Default | Meaning |
|---|---|---|---|
| `SNAPSHOT` | injected | — | Konflux Snapshot JSON. |
| `TARGET_KUBECONFIG_SECRET` | yes | — | Secret name in the PipelineRun namespace with the target cluster kubeconfig. |
| `TARGET_KUBECONFIG_SECRET_KEY` | no | `kubeconfig` | Key inside that Secret. |
| `SCANNER_IMAGE` | no | from Snapshot | Override to pin a released operator image. |
| `COMPONENT_NAME` | no | `tls-compliance-operator` | Snapshot component name used when `SCANNER_IMAGE` is empty. |
| `SCAN_NAMESPACE` | no | `tls-compliance-operator` | Namespace on the **target** cluster where the Job and CRDs are created. |
| `INCLUDE_NAMESPACES` | no | `""` (all) | Comma-separated namespaces to scan. |
| `EXCLUDE_NAMESPACES` | no | `""` (none) | Comma-separated namespaces to exclude. |
| `OUTPUT_FORMAT` | no | `junit` | Output format: `csv`, `json`, `yaml`, `junit`, `markdown`, `html`, `sarif`. |
| `WORKERS` | no | `"10"` | Concurrent scan workers. |
| `JOB_TIMEOUT_SECONDS` | no | `"3600"` | Wait budget for the Job. |

The pipeline installs the operator's CRDs, creates a ClusterRole with the
required RBAC permissions, deploys a run-once scan Job, waits for completion,
copies the results, and cleans up. It writes Tekton result `TEST_OUTPUT` as:

```json
{"result":"SUCCESS|FAILURE|ERROR","timestamp":"...","note":"...","failures":0,"successes":1,"warnings":0}
```

### Exit code semantics

| Code | Meaning | TEST_OUTPUT |
|------|---------|-------------|
| 0 | All endpoints TLS-compliant | `SUCCESS` |
| 1 | Non-compliant endpoints found (NonCompliant, NoTLS, PlaintextHTTP) | `FAILURE` |
| 2 | Scan error | `ERROR` |

Infrastructure statuses like `Timeout` and `Unreachable` do **not** trigger
failure. This prevents transient network issues from failing CI pipelines.

### What the operator scans

- **Services** — ClusterIP, ExternalName, NodePort, and LoadBalancer endpoints
- **Ingresses** — all TLS hosts
- **Routes** (OpenShift) — edge/reencrypt/passthrough TLS
- **Gateway API** — HTTPRoute, TLSRoute, and Gateway listeners
- **Pods** — direct pod IP scanning for operand coverage
- **PQC/ML-KEM** — active probing for X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024

Each endpoint gets a `TLSComplianceReport` CR with TLS version support,
cipher suites, certificate details, PQC readiness classification
(`PQCReady`/`TLS13Capable`/`LegacyTLS`/`NoPQC`), and a compliance grade.

### Target cluster privileges

The kubeconfig in `TARGET_KUBECONFIG_SECRET` must be able to:

- Create namespaces, ServiceAccounts, Jobs
- Create/delete CRDs (`apiextensions.k8s.io`)
- Create ClusterRole / ClusterRoleBinding
- `oc cp` from the scanner pod

Unlike tls-scanner, the operator does **not** need privileged SCC or pods/exec
access.

## Standardized test result

Integration Service recognizes the Tekton result named **`TEST_OUTPUT`** only.
Custom result names will not appear as PR checks.

## Comparison with tls-scanner

Both tools can scan cluster endpoints. Key differences:

| | tls-compliance-operator | tls-scanner |
|---|---|---|
| PQC detection | Active ML-KEM probing + passive curve detection | `--pqc-check` flag |
| Output formats | CSV, JSON, YAML, JUnit, Markdown (native) | JSON, CSV, JUnit |
| CRDs | Creates `TLSComplianceReport` CRs per endpoint | No CRDs |
| RBAC | Standard read-only (no privileged SCC) | Privileged SCC + pods/exec |
| Namespace filtering | `--include-namespaces` / `--exclude-namespaces` | `--namespace-filter` |
| CI mode | `--run-once` with exit codes | Inline binary execution |

## Phase notes

- **Phase 1 (this directory):** onboard build + smoke/self-test + reusable
  compliance pipeline for consumers that already have a kubeconfig Secret.
- **Later:** pin consumer `revision` values to released tags; tighten RBAC;
  optional ITS for scanning core OCP components under Konflux.
