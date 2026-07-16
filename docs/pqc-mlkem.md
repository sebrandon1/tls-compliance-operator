# Post-Quantum Cryptography (ML-KEM)

The operator detects whether TLS endpoints support post-quantum key exchange,
helping you track your cluster's readiness for the transition to
quantum-resistant cryptography.

## What is ML-KEM?

ML-KEM (Module-Lattice Key Encapsulation Mechanism, FIPS 203) is the first
NIST-standardized post-quantum key exchange algorithm. In TLS 1.3, it is
deployed as **hybrid** key exchanges that combine a classical ECDH algorithm
with ML-KEM, so the connection remains secure even if one of the two
algorithms is broken.

Go 1.26 supports three hybrid ML-KEM curves, all included in the default
TLS 1.3 curve preferences:

| Curve Name | Classical + PQ Components |
|------------|--------------------------|
| `X25519MLKEM768` | X25519 + ML-KEM-768 |
| `SecP256r1MLKEM768` | ECDH P-256 + ML-KEM-768 |
| `SecP384r1MLKEM1024` | ECDH P-384 + ML-KEM-1024 |

The operator detects all three hybrid curves via both passive detection and
active probing.

### Hybrid vs Pure ML-KEM

All ML-KEM curves currently available in Go's `crypto/tls` are **hybrid** —
they pair a classical key exchange with ML-KEM. This means the connection is
protected by both algorithms simultaneously.

Pure ML-KEM (without a classical component) is not yet available in Go's TLS
implementation. Some government requirements (e.g., CNSA 2.0) may eventually
mandate pure ML-KEM. When pure ML-KEM curve IDs are standardized and added to
Go, the operator will detect them automatically via the existing `"MLKEM"`
substring match on negotiated curve names.

## Detection Methods

The operator uses two complementary approaches:

### Passive Detection

During standard TLS probing, the operator records the key exchange curve
negotiated for each TLS version. If the server negotiates `X25519MLKEM768`,
the `quantumReady` field is set to `true`. This is opportunistic — it depends
on the curve preferences the client and server agree on during the handshake.

### Active ML-KEM Probing

When passive detection does not find ML-KEM but the endpoint supports TLS 1.3,
the operator performs a second handshake offering **only** the three hybrid
ML-KEM curves (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`).
If the server completes this handshake with any of them, the `mlkemSupported`
field is set to `true`.

This is a definitive test: if the server cannot handle any hybrid ML-KEM curve,
the connection fails and the field stays `false`. Active probing is skipped
when TLS 1.3 is not supported or when passive detection already found ML-KEM.

## PQC Readiness Classification

Each endpoint is classified into one of four readiness levels:

| Level | Meaning |
|-------|---------|
| **PQCReady** | TLS 1.3 supported and hybrid ML-KEM confirmed (via passive or active detection) |
| **TLS13Capable** | TLS 1.3 supported but ML-KEM not detected |
| **LegacyTLS** | Only TLS 1.2 or older — no path to PQC without TLS 1.3 |
| **NoPQC** | No TLS detected at all |

The classification is determined by `determinePQCReadiness()` using this logic:

1. No TLS version supported at all → **NoPQC**
2. TLS 1.3 not supported → **LegacyTLS**
3. `mlkemSupported` is true OR negotiated curve contains "MLKEM" (any hybrid variant) → **PQCReady**
4. Otherwise → **TLS13Capable**

## CRD Status Fields

The `TLSComplianceReport` status includes four PQC-related fields:

| Field | Type | Description |
|-------|------|-------------|
| `pqcReadiness` | enum | Classification level (PQCReady, TLS13Capable, LegacyTLS, NoPQC) |
| `quantumReady` | bool | True if passive detection found a post-quantum key exchange curve |
| `mlkemSupported` | bool | True if active probing confirmed hybrid ML-KEM support |
| `negotiatedCurves` | map | Per-TLS-version key exchange curve (e.g., `"TLS 1.3": "X25519MLKEM768"`) |

## Viewing PQC Status

### List view

The `PQC` column appears in default `kubectl get` output:

```bash
$ kubectl get tlsreport
NAME                         HOST          PORT   SOURCE   COMPLIANCE   GRADE   FS     TLS1.3   TLS1.2   TLS1.0   PQC            CERTEXPIRY   AGE
google-com-443-01d44386      google.com    443    Target   Compliant    B       true   true     true     true     PQCReady       53           2m
my-service-default-443-...   my-svc.ns     443    Service  Compliant    A       true   true     false    false    TLS13Capable   364          5m
```

### Wide view

Wide output adds the `ML-KEM` column showing active probe results:

```bash
$ kubectl tlsreport get -o wide
```

### Detailed view

```bash
$ kubectl describe tlsreport google-com-443-01d44386
```

The PQC section shows:

```
Negotiated Curves:
  TLS 1.2:  X25519
  TLS 1.3:  X25519MLKEM768
Quantum Ready:      true
ML-KEM Supported:   true
PQC Readiness:      PQCReady
```

### Conditions

The `PQCCompliant` condition provides programmatic access:

```
Conditions:
  Type: PQCCompliant  Status: True   Reason: PQCReady
    Message: Endpoint supports TLS 1.3 with ML-KEM key exchange (verified by active probe)
```

Possible condition states:

| Status | Reason | Message |
|--------|--------|---------|
| True | PQCReady | Endpoint supports TLS 1.3 with hybrid ML-KEM key exchange (verified by active probe) |
| True | PQCReady | Endpoint supports TLS 1.3 with hybrid ML-KEM key exchange |
| False | TLS13Capable | Endpoint supports TLS 1.3 but has not negotiated a post-quantum key exchange |
| False | LegacyTLS | Endpoint only supports TLS 1.2 or older, no path to post-quantum cryptography |
| Unknown | NoPQC | No TLS detected on endpoint |

## Filtering and Sorting

Filter reports by PQC readiness:

```bash
# Only PQC-ready endpoints
kubectl tlsreport csv --pqc-status PQCReady

# Endpoints not yet PQC-ready (TLS 1.3 but no ML-KEM)
kubectl tlsreport csv --pqc-status TLS13Capable

# Legacy endpoints (no TLS 1.3)
kubectl tlsreport csv --pqc-status LegacyTLS

# Combine with other filters
kubectl tlsreport json --source Service --pqc-status TLS13Capable -n production
```

Sort by PQC readiness:

```bash
kubectl tlsreport csv --sort-by pqc
```

## Summary View

`kubectl tlsreport summary` includes a PQC readiness section:

```
Post-Quantum Cryptography Readiness
  PQC Ready Rate:                12.5%
  ML-KEM Supported (active probe): 3
  PQCReady:       3
  TLS13Capable:   15
  LegacyTLS:      5
  NoPQC:          1
```

## Prometheus Metrics

The `tls_compliance_pqc_readiness` gauge tracks PQC status per endpoint using
one-hot encoding:

```promql
# Count of PQC-ready endpoints
count(tls_compliance_pqc_readiness{readiness="PQCReady"} == 1)

# Percentage of PQC-ready endpoints
count(tls_compliance_pqc_readiness{readiness="PQCReady"} == 1)
/ count(tls_compliance_pqc_readiness{readiness="PQCReady"})
* 100

# Endpoints capable of PQC but not yet ready
count(tls_compliance_pqc_readiness{readiness="TLS13Capable"} == 1)
```

## Kubernetes Events

The operator emits events when PQC readiness changes:

| Event | Type | Reason | Description |
|-------|------|--------|-------------|
| Became PQC-ready | Normal | `PQCReady` | Endpoint is now post-quantum ready (TLS 1.3 + ML-KEM) |
| PQC readiness degraded | Warning | `PQCNotReady` | PQC readiness changed (e.g., PQCReady → TLS13Capable) |

```bash
kubectl get events --field-selector reason=PQCReady
kubectl get events --field-selector reason=PQCNotReady
```

---

Back to [Viewing Reports](viewing-reports.md) | [README](../README.md)
