# Feature Comparison: tls-compliance-operator vs openshift/tls-scanner

[openshift/tls-scanner](https://github.com/openshift/tls-scanner) is a
single-shot, Job-based TLS configuration scanner from the OpenShift team. This
operator is independently developed but shares the scanner's problem space. Both
detect which TLS versions and ciphers an endpoint offers, check it against the
OpenShift TLS security profiles, and report post-quantum (ML-KEM) readiness.

The difference is the execution model: the scanner runs once as a batch Job and
writes files; the operator runs continuously, persists results as Kubernetes
objects, and exposes them through the API, events, Prometheus, and a CLI plugin.
This document compares the two feature-by-feature and records any remaining
parity gaps.

## Comparison basis

| | |
|---|---|
| Upstream repo | [`openshift/tls-scanner`](https://github.com/openshift/tls-scanner) |
| Upstream revision | `main` @ [`df6f8d46`](https://github.com/openshift/tls-scanner/tree/df6f8d46) ("Merge pull request #64 … junit-metadata", 2026-10-20) |
| Checked | 2026-11-24 |
| This repo | `tls-compliance-operator` @ [`v1.2.2`](https://github.com/sebrandon1/tls-compliance-operator/tree/v1.2.2) |

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
| Discovery | Kubernetes API: Service, Ingress, Route, Gateway API, Pod, `TLSComplianceTarget`; optional exec `/proc/net/tcp{,6}` discovery | Pod `Status.PodIP` + exec `/proc/net/tcp{,6}`; `--targets`/`--template` |
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
| Pod discovery | Running pods; declared container ports; optional exec `/proc/net/tcp{,6}` discovery | All pods; exec `/proc/net/tcp{,6}` with declared-port fallback | Shared |
| Undeclared in-container listeners | Yes — `--discover-listening-ports` execs `/proc/net/tcp{,6}` | Yes — reads the socket table inside the container | Shared |
| Service discovery | ClusterIP, ExternalName, NodePort, LoadBalancer, headless/EndpointSlice | None (pod-IP centric) | Operator-only |
| Ingress / OpenShift Route | Yes | No | Operator-only |
| Gateway API (HTTPRoute/TLSRoute/GRPCRoute/Gateway) | Yes, auto-detected via REST mapper | No | Operator-only |
| Arbitrary host:port targets | `TLSComplianceTarget` CRD + validating webhook | `-host`/`-port`, `--targets`, `--template` | Equivalent |
| Curated target template | `kubectl tlsreport target import/export` (JSON/YAML) alongside `TLSComplianceTarget` CRs | `--template`, `--generate-template` | Shared |
| Namespace filtering | `--include-namespaces` + `--exclude-namespaces` | `--namespace-filter` (exact list) | Shared |
| Component filtering | `--source` kind filter plus regex per-component policy (`TLSSecurityProfile` CR) | `--component-filter` | Shared (different mechanism) |
| Dry-run / target preview | Operator `--dry-run`; `kubectl tlsreport target` preview | `--dry-run` | Shared |
| IPv6 | Dual-stack pod IPs; IPv6 literals allowed for targets | `testssl.sh -6` | Shared |
| Host network / MicroShift | `--scan-host-ports` for host listeners; `config/microshift/` privileged hostNetwork recipe | `SCAN_MODE=host` + `ss -lntp`, ports 2000–30000, with a MicroShift template | Shared |

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
| Named groups / curves | Reported per endpoint; `--expected-groups` with `contains`/`exact` and `--fail-on-group-mismatch` | Reported; `--expected-groups` with `contains`/`exact` | Shared |
| ALPN (h2, http/1.1) | Yes | Not exposed | Operator-only |
| PQC / ML-KEM readiness | Passive detection + active ML-KEM handshake; 4-level readiness | testssl KEM findings; 4-level readiness; `--pqc-check` gate | Shared (different means) |
| STARTTLS | 12 protocols: SMTP, IMAP, LDAP, PostgreSQL, MySQL, POP3, LMTP, XMPP, XMPP-server, NNTP, Sieve, FTP | 13 protocol names accepted by testssl, with process-based auto-detection | Shared (upstream also does telnet) |
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
| Trust-chain validation | Yes — `verifyPeerChain` for direct TLS and STARTTLS | No | Operator-only |
| Revocation (OCSP/CRL) | No | No | Neither |

### Compliance and policy

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| OpenShift APIServer/IngressController/KubeletConfig profiles | Yes, periodically refreshed | Yes, read per run | Shared |
| `tlsAdherence` handling | Yes, reported and used in status | Yes, gates enforcement | Shared |
| Per-component profile mapping | Regex policy per namespace/process/port/component with `exempt`, hot-reloaded from a ConfigMap, plus exemption reasons and expiry dates | Embedded `policy.yaml` (namespace/process/port/component regex, first match wins, `exempt` profile) | Shared (operator adds hot reload and expiry) |
| Expected-groups assertion | `--expected-groups` + `--expected-groups-mode` + `--fail-on-group-mismatch` | `--expected-groups` + `--expected-groups-mode` | Shared |
| PQC-only quick gate | `--require-pqc` (TLS 1.3 + ML-KEM, non-zero exit) | `--pqc-check` (TLS 1.3 + ML-KEM, non-zero exit) | Shared |
| Pass/fail exit gating | `--run-once` exit codes; `--fail-on-non-compliant` in the plugin | Policy and `--pqc-check` exit codes | Equivalent |
| Endpoint status classification | 13 statuses + 5 conditions | 5 statuses (`OK`, `NO_TLS`, `LOCALHOST_ONLY`, `NO_PORTS`, `PROBE_PORT`) | Operator-only |
| Localhost-only listener detection | Yes (`LocalhostOnly`, with all observed bind addresses recorded) | Yes (`LOCALHOST_ONLY`, with listen-address precedence) | Shared |

### Output, reporting, and CI

| Capability | tls-compliance-operator | openshift/tls-scanner | Status |
|---|---|---|---|
| Persistent results | `TLSComplianceReport` CRDs | Files in `emptyDir`, copied out | Operator-only |
| Prometheus metrics | `tls_compliance_*` (30+ metrics) | No | Operator-only |
| Kubernetes events | Yes (compliance, cert, PQC, discovery) | No | Operator-only |
| JSON | Yes | Yes | Shared |
| CSV | Yes | Yes (39 columns + a separate errors CSV) | Shared |
| JUnit XML | Yes, cases named `ns/<ns> <Kind>/<name> port/<n>`, tagged `[OCPFeatureGate:TLSAdherence]` when adherence is asserted | Yes, cases keyed by namespace/workload/port with `[OCPFeatureGate:TLSAdherence]` | Shared |
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

No tracked parity gaps remain. Every gap listed in the previous revision of this
document has shipped:

- **Broader STARTTLS** (#657) — `pkg/tlscheck/starttls.go` now implements 12
  protocols, including MySQL, POP3, LMTP, XMPP, NNTP, Sieve, and FTP.
- **Gate-friendly JUnit names** (#658) — cases are keyed by namespace, workload,
  and port, with the `[OCPFeatureGate:TLSAdherence]` tag.
- **Expected-groups assertion** (#659) — `--expected-groups`,
  `--expected-groups-mode`, and `--fail-on-group-mismatch`.
- **PQC-only gate** (#660) — `--require-pqc` gates on TLS 1.3 + ML-KEM.
- **TLS profile override** (#661) — `--tls-profile-type` for HyperShift.
- **Per-component policy with exemptions** (#662, #702) — the
  `TLSSecurityProfile` CR with regex rules, `exempt`, hot reload, and exemption
  reasons/expiry.
- **Dry-run and target import/export** (#663) — operator `--dry-run` and
  `kubectl tlsreport target import|export`.
- **MicroShift host-mode recipe** (#664) — `--scan-host-ports` and
  `config/microshift/`.

In-container undeclared-listener discovery (#655) and trust-chain validation
(#724) also landed, so those rows moved from "Upstream-only"/"Neither" to shared
or operator-only.

Two differences remain, and neither is a tracked gap:

- **telnet STARTTLS** — testssl accepts 13 STARTTLS protocol names; the operator
  implements 12 (all but telnet). Add `telnet` to `starttlsProtocolNames` in
  `pkg/tlscheck/starttls.go` if that protocol is ever needed.
- **Revocation (OCSP/CRL)** — neither tool checks revocation; see
  [Deliberate non-goals](#deliberate-non-goals).

Explicitly **not** gaps:

- Running `testssl.sh` — the operator uses native Go `crypto/tls`; engine choice
  is an architectural difference, not a missing feature.
- `--targets`/`--template` — `TLSComplianceTarget` CRs and `target import/export`
  are the operator's equivalent.
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
- **Revocation (OCSP/CRL)** — neither tool checks revocation today. Probing OCSP
  responders adds an outbound dependency per endpoint and is not part of the
  scanner's model either; treat it as a future enhancement, not a parity gap.

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
