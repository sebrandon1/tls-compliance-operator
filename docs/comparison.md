# Feature Comparison: tls-compliance-operator vs openshift/tls-scanner

[openshift/tls-scanner](https://github.com/openshift/tls-scanner) is a
single-shot, Job-based TLS configuration scanner from the OpenShift team. This
operator is independently developed but shares the scanner's problem space. Both
detect which TLS versions and ciphers an endpoint offers, check it against the
OpenShift TLS security profiles, and report post-quantum (ML-KEM) readiness.

The difference is the execution model: the scanner runs once as a batch Job and
writes files; the operator runs continuously, persists results as Kubernetes
objects, and exposes them through the API, events, Prometheus, and a CLI plugin.
This document compares the two feature-by-feature and records the remaining
parity gaps.

## Comparison basis

| | |
|---|---|
| Upstream repo | [`openshift/tls-scanner`](https://github.com/openshift/tls-scanner) |
| Upstream revision | `main` @ [`df6f8d46`](https://github.com/openshift/tls-scanner/tree/df6f8d46) ("Merge pull request #64 … junit-metadata", 2026-10-20) |
| Checked | 2026-11-05 |
| This repo | `tls-compliance-operator` @ `b352119` (v1.1.22) |

Upstream has **no git tags and no GitHub releases** — it versions by long-lived
`release-*` branches — so the comparison is pinned to a commit. Upstream's own
README is known to drift from its code (see [PR #106](https://github.com/openshift/tls-scanner/pull/106));
claims below were verified against the pinned **source**, not the upstream README.

To refresh this comparison, re-read upstream's
[`cmd/tls-scanner/main.go`](https://github.com/openshift/tls-scanner/blob/df6f8d46/cmd/tls-scanner/main.go)
(flags),
[`internal/output/`](https://github.com/openshift/tls-scanner/tree/df6f8d46/internal/output)
(CSV/JSON/JUnit fields), and
[`internal/scanner/policy.yaml`](https://github.com/openshift/tls-scanner/blob/df6f8d46/internal/scanner/policy.yaml)
(compliance policy), then update the revision and date above.

## At a glance

| Aspect | tls-compliance-operator | openshift/tls-scanner |
|---|---|---|
| Execution | Long-running controller; watches + periodic rescans | One-shot Job (or CronJob); optional MicroShift host mode |
| TLS engine | Native Go `crypto/tls` (`pkg/tlscheck/`) | Shells out to `testssl.sh` 3.2.2 |
| Discovery | Kubernetes API: Service, Ingress, Route, Gateway API, Pod, `TLSComplianceTarget` | Pod `Status.PodIP` + exec `/proc/net/tcp{,6}`; `--targets`/`--template` |
| Results | `TLSComplianceReport` CRDs, events, Prometheus, export files | JSON / CSV / JUnit / timing / log files copied out of the Job |
| Compliance | Per-endpoint status + conditions; profile adherence | Per-run policy engine + exit codes / JUnit failures |
| Deployment | OLM bundle, `install.yaml`, Krew plugin | `deploy.sh`, Job templates; no OLM/Helm |
| Versioning | Tagged releases, published images | No tags/releases; release branches |

## Capability matrix

**Status legend**

- **Shared** — both tools implement the capability.
- **Operator-only** — only this operator implements it.
- **Upstream-only** — only `openshift/tls-scanner` implements it.
- **Equivalent** — both implement it, via different mechanisms.
- **Partial** — both implement something, but one is materially narrower.
- **Neither** — neither tool implements it.

### Discovery and targeting

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| Pod discovery | Running pods; declared container ports | All pods; exec `/proc/net/tcp{,6}` with declared-port fallback | Shared (upstream deeper) |
| Undeclared in-container listeners | No — declared ports + TLS-port heuristic | Yes — reads the socket table inside the container | Upstream-only |
| Service discovery | ClusterIP, ExternalName, NodePort, LoadBalancer, headless/EndpointSlice | None (pod-IP centric) | Operator-only |
| Ingress / OpenShift Route | Yes | No | Operator-only |
| Gateway API (HTTPRoute/TLSRoute/GRPCRoute/Gateway) | Yes, auto-detected via REST mapper | No | Operator-only |
| Arbitrary host:port targets | `TLSComplianceTarget` CRD + validating webhook | `-host`/`-port`, `--targets`, `--template` | Equivalent |
| Curated target template | No (use CRs) | `--template`, `--generate-template` | Upstream-only |
| Namespace filtering | `--include-namespaces` + `--exclude-namespaces` | `--namespace-filter` (exact list) | Shared |
| Component filtering | No (filter by source kind instead) | `--component-filter` | Upstream-only |
| Dry-run / target preview | No | `--dry-run` | Upstream-only |
| IPv6 | Dual-stack pod IPs; IPv6 literals allowed for targets | `testssl.sh -6` | Shared |
| Host network / MicroShift | hostNetwork pods and NodePort/LB endpoints; no dedicated host-mode recipe | `SCAN_MODE=host` + `ss -lntp`, ports 2000–30000, with a MicroShift template | Partial |

### TLS and crypto probing

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| TLS 1.0–1.3 detection | Yes, concurrent probes | Yes (testssl `-p`) | Shared |
| SSLv3 detection | Dedicated SSLv3 ClientHello probe | testssl reports SSLv2/SSLv3 where offered | Shared |
| Cipher suites per version | Yes (enumerated, capped at 20/version) | Yes (testssl `-E`) | Shared |
| IANA ↔ OpenSSL cipher names | Yes | Yes, for profile comparison | Shared |
| Cipher strength grading (A–F) | Yes | No | Operator-only |
| Server cipher preference | Yes (opt-in) | Not exposed | Operator-only |
| Forward secrecy / key exchange | Yes | Yes (`FS_ECDHE_curves`, KEM groups) | Shared |
| Named groups / curves | Reported per endpoint; checked against profile groups | Reported; `--expected-groups` with `contains`/`exact` | Shared (upstream asserts) |
| ALPN (h2, http/1.1) | Yes | Not exposed | Operator-only |
| PQC / ML-KEM readiness | Passive detection + active ML-KEM handshake; 4-level readiness | testssl KEM findings; 4-level readiness; `--pqc-check` gate | Shared (different means) |
| STARTTLS | SMTP (25/587), IMAP (143), LDAP (389), PostgreSQL (5432) | 13 protocol names accepted by testssl with process-based auto-detection (incl. MySQL, POP3, XMPP, NNTP, Sieve) | Partial |
| SNI / hostname-aware probing | `ServerName` set from the endpoint host | Targets are IP:port; hostname virtual-host targeting was not adopted (PR #88 closed) | Operator-only |
| mTLS-required detection | Yes, via TLS alerts | No distinct status | Operator-only |
| Client certificates (probing mTLS) | Yes (`--client-cert` / `--client-key`) | No | Operator-only |
| Timeouts | Per-check timeout | Per-target and per-connect timeouts | Shared |
| Retries / backoff | Configurable per-check retries with exponential backoff | No per-probe retries (the Job's `backoffLimit` restarts the whole Job) | Operator-only |
| Rate limiting / concurrency | Global and per-namespace rate limits; worker pool | `-j` parallel testssl jobs | Equivalent |

### Certificate checks

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| Issuer, subject, DNS/IP SANs, serial, SHA-256 fingerprint | Yes | No | Operator-only |
| Validity window and expiry tracking | Yes, with configurable warning threshold | No | Operator-only |
| Chain length and hostname match | Yes | No | Operator-only |
| Public key algorithm/bits, signature algorithm | Yes | Certificate signature algorithms only | Shared (operator broader) |
| Image certificate enrichment | Yes, via imagecertinfo-operator | No | Operator-only |
| Trust, revocation/OCSP, trust-chain validation | No | No | Neither |

### Compliance and policy

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| OpenShift APIServer/IngressController/KubeletConfig profiles | Yes, periodically refreshed | Yes, read per run | Shared |
| `tlsAdherence` handling | Yes, reported and used in status | Yes, gates enforcement | Shared |
| Per-component profile mapping | Component status fields; no regex policy or exemptions | Embedded `policy.yaml` (namespace/process/port/component regex, first match wins, `exempt` profile) | Partial |
| Expected-groups assertion | No standalone assertion mode | `--expected-groups` + `--expected-groups-mode` | Upstream-only |
| PQC-only quick gate | No (PQC readiness is reported) | `--pqc-check` (TLS 1.3 + ML-KEM, non-zero exit) | Upstream-only |
| Pass/fail exit gating | `--run-once` exit codes; `--fail-on-non-compliant` in the plugin | Policy and `--pqc-check` exit codes | Equivalent |
| Endpoint status classification | 12 statuses + 4 conditions | 5 statuses (`OK`, `NO_TLS`, `LOCALHOST_ONLY`, `NO_PORTS`, `PROBE_PORT`) | Operator-only |
| Localhost-only listener detection | No — `Filtered` status is reserved but never emitted | Yes (`LOCALHOST_ONLY`, with listen-address precedence) | Upstream-only |

### Output, reporting, and CI

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| Persistent results | `TLSComplianceReport` CRDs | Files in `emptyDir`, copied out | Operator-only |
| Prometheus metrics | `tls_compliance_*` (20+ metrics) | No | Operator-only |
| Kubernetes events | Yes (compliance, cert, PQC, discovery) | No | Operator-only |
| JSON | Yes | Yes | Shared |
| CSV | Yes | Yes (39 columns + a separate errors CSV) | Shared |
| JUnit XML | Yes, cases named `host:port` | Yes, cases keyed by namespace/workload/port with `[OCPFeatureGate:TLSAdherence]` | Shared (upstream gate-friendly) |
| YAML, Markdown, HTML, SARIF | Yes | No | Operator-only |
| Raw CR export / describe | Yes (`--raw`, `kubectl tlsreport describe`) | No | Operator-only |
| Filtering, sorting, summary | Yes (status, source, PQC, expiry, grade, issuer, …) | Scan-time filters and dry-run tables | Operator-only |
| Snapshot diff between runs | Yes | No | Operator-only |
| Timing report | `scanDuration` per report + metrics | `--timing-file` | Equivalent |
| Compliance history / audit trail | Bounded `status.history` per endpoint | No (one-shot output only) | Operator-only |

### Kubernetes-native integration and operations

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| Watch-driven continuous reconcile | Yes | No | Operator-only |
| Periodic rescan | Yes (`--scan-interval`) | CronJob | Equivalent |
| Leader election / HA | Yes | No | Operator-only |
| Admission webhook | Yes (`TLSComplianceTarget` defaulting/validation) | No | Operator-only |
| Retention / TTL cleanup | Yes | `emptyDir` discarded with the Job | Operator-only |
| Circuit breaker for failing endpoints | Yes | No | Operator-only |
| SSRF / reserved-host validation | Yes | N/A (in-cluster only) | Operator-only |
| FIPS mode detection | Yes | No | Operator-only |
| Multi-arch images | amd64, arm64, s390x, ppc64le | amd64, arm64, s390x, ppc64le | Shared |
| OLM bundle / install manifest / Krew plugin | Yes | No (deploy script and Job templates only) | Operator-only |
| must-gather / Compliance Operator integration | No | No | Neither |
| Automated remediation | No | No | Neither |

## Parity gaps to close

Upstream capabilities this operator does not yet match, ranked by expected value.
Each entry links to a tracked issue with an implementation plan and testing goal.

| Issue | Gap | What upstream does | What the operator does today | Where to change |
|---|---|---|---|---|
| [#655](https://github.com/sebrandon1/tls-compliance-operator/issues/655) | **Undeclared port discovery** | Execs into each pod and reads `/proc/net/tcp{,6}` to find every listener, not just declared `containerPort`s | Uses declared container ports plus a TLS-port heuristic (`isTLSContainerPort`) | `pkg/endpoint/resolver.go` (`ExtractFromPod`); needs an exec/kubelet path and RBAC |
| [#656](https://github.com/sebrandon1/tls-compliance-operator/issues/656) | **Localhost-only detection** | Emits `LOCALHOST_ONLY` by comparing the listen address, so loopback-only ports are not reported as failures | Probes the pod IP and never distinguishes a loopback-bound listener; `ComplianceStatusFiltered` is reserved but unused | `pkg/tlscheck/types.go`, `api/v1alpha1/tlscompliancereport_types.go`, `pkg/endpoint/resolver.go` |
| [#657](https://github.com/sebrandon1/tls-compliance-operator/issues/657) | **Broader STARTTLS** | 13 protocol names accepted by testssl (incl. MySQL, POP3, XMPP, NNTP, Sieve); postgres/mysql auto-detected from process names | SMTP, IMAP, LDAP, PostgreSQL only | `pkg/tlscheck/starttls.go` (add at least MySQL) |
| [#658](https://github.com/sebrandon1/tls-compliance-operator/issues/658) | **Gate-friendly JUnit naming** | Stable case names keyed by namespace/workload/port, plus the `OCPFeatureGate:TLSAdherence` tag | Cases named `host:port` | `pkg/export/junit.go` |
| [#659](https://github.com/sebrandon1/tls-compliance-operator/issues/659) | **Expected-groups assertion** | `--expected-groups` with `contains`/`exact` over advertised curves, independent of profiles | Reports `negotiatedCurves` and checks profile groups, but exposes no assertion or gate | `pkg/export/` (filter/gate) and `cmd/kubectl-tlsreport/` |
| [#660](https://github.com/sebrandon1/tls-compliance-operator/issues/660) | **PQC-only gate** | `--pqc-check` requires TLS 1.3 + ML-KEM and exits non-zero otherwise | Reports PQC readiness; `--fail-on-non-compliant` covers overall compliance, not a PQC-only check | `cmd/kubectl-tlsreport/main.go`, `pkg/export/compliance.go` |
| [#661](https://github.com/sebrandon1/tls-compliance-operator/issues/661) | **TLS profile override (HyperShift)** | `--tls-profile-type Old\|Intermediate\|Modern` skips reading `APIServer/cluster` | The profile fetcher always reads the cluster CR | `pkg/tlsprofile/fetcher.go`, `cmd/main.go` flags |
| [#662](https://github.com/sebrandon1/tls-compliance-operator/issues/662) | **Component policy with exemptions** | Embedded regex policy mapping namespace/process/port/component to a profile, including `exempt` | Applies profile checks by component status; no exemption mechanism | `pkg/tlsprofile/`, `internal/controller/conditions.go` — decide whether exempt rules belong in an operator |
| [#663](https://github.com/sebrandon1/tls-compliance-operator/issues/663) | **Discovery conveniences** | `--dry-run` target preview and `--generate-template` | No preview command; arbitrary targets are created as CRs | `cmd/kubectl-tlsreport/` (low priority) |
| [#664](https://github.com/sebrandon1/tls-compliance-operator/issues/664) | **MicroShift host-mode recipe** | Dedicated privileged hostNetwork Job scanning host listeners on ports 2000–30000 | Scans hostNetwork pods and NodePort/LB endpoints, but ships no host-mode deployment recipe | `config/` + docs (recipe only) |

Explicitly **not** gaps:

- Running `testssl.sh` — the operator uses native Go `crypto/tls`; engine choice
  is an architectural difference, not a missing feature.
- `--targets`/`--template` — `TLSComplianceTarget` CRs are the operator's equivalent.
- File artifacts — the operator's export formats and `--run-once` cover the same use.
- IPv6, certificate signature algorithms, SSLv3 — already supported.

## Deliberate non-goals

These upstream behaviors are intentionally not replicated, because they are
properties of a batch scanner rather than an operator:

- **One-shot Job semantics and artifact files** — the operator persists to CRs and
  exports on demand (`kubectl tlsreport csv|json|yaml|junit|…`), with `--run-once`
  for CI.
- **Shelling out to `testssl.sh`** — native Go probing avoids an external binary,
  a privileged container, and text parsing, and enables rate limiting, retries,
  circuit breaking, and per-endpoint metrics.
- **`--limit-ips` and scan-time `--component-filter`** — operator scans are scoped
  by namespace and source kind instead.

## Automated behavioral parity test

`make test-parity` (`test/parity/parity_test.go`, nightly via
`.github/workflows/nightly-parity.yml`) covers **behavioral** parity, not feature
parity:

- Six scenarios — TLS 1.3 only, TLS 1.2 only, TLS 1.2+1.3, plain HTTP, mTLS
  required, expired certificate.
- Asserts only TLS detection and the TLS 1.0–1.3 booleans; cipher suites,
  certificates, forward secrecy, PQC/ML-KEM, ALPN, and mTLS are recorded in a gap
  report but not compared.
- Runs the upstream scanner from `quay.io/bapalm/tls-scanner:latest`, rebuilt
  nightly from upstream `main` with no SHA pin, so its baseline can drift.

This document is the feature-level complement to that suite.

## References

Upstream, pinned to `df6f8d46`:

- [CLI flags and orchestration](https://github.com/openshift/tls-scanner/blob/df6f8d46/cmd/tls-scanner/main.go)
- [testssl.sh invocation and parsing](https://github.com/openshift/tls-scanner/blob/df6f8d46/internal/scanner/scanner.go)
- [Component policy](https://github.com/openshift/tls-scanner/blob/df6f8d46/internal/scanner/policy.yaml)
- [CSV output](https://github.com/openshift/tls-scanner/blob/df6f8d46/internal/output/csv.go) · [JSON output](https://github.com/openshift/tls-scanner/blob/df6f8d46/internal/output/json.go) · [JUnit output](https://github.com/openshift/tls-scanner/blob/df6f8d46/internal/output/junit.go)

Notable upstream changes reflected above: certificate signature algorithms
([#93](https://github.com/openshift/tls-scanner/pull/93)), IPv6 scanning
([#95](https://github.com/openshift/tls-scanner/pull/95)), `FS_ECDHE_curves`
([#98](https://github.com/openshift/tls-scanner/pull/98)), `--expected-groups`
([#100](https://github.com/openshift/tls-scanner/pull/100)), stable JUnit names
([#90](https://github.com/openshift/tls-scanner/pull/90),
[#104](https://github.com/openshift/tls-scanner/pull/104)), hostPID port-ownership
scoping ([#105](https://github.com/openshift/tls-scanner/pull/105)), and README
drift ([#106](https://github.com/openshift/tls-scanner/pull/106)).

Operator internals: `pkg/tlscheck/`, `pkg/endpoint/`, `pkg/export/`,
`pkg/tlsprofile/`, `pkg/hostvalidation/`, `internal/controller/`,
`internal/metrics/`, `cmd/kubectl-tlsreport/`.
