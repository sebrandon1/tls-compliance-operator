# Viewing Reports

## List All Reports

```bash
$ kubectl get tlsreport
NAME                                                           HOST                                                  PORT    SOURCE    COMPLIANCE   GRADE   FS     TLS1.3   TLS1.2   TLS1.0   PQC            CERTEXPIRY   AGE
rhcos4-moderate-master-rs-openshift-compliance-8443-03744f25   rhcos4-moderate-master-rs.openshift-compliance         8443    Service   Compliant    A       true   true     false    false    TLS13Capable   0            5m
google-com-443-01d44386                                        google.com                                            443     Target    Compliant    B       true   true     true     true     PQCReady       53           2m
ocp4-cis-rs-openshift-compliance-8443-aab74008                 ocp4-cis-rs.openshift-compliance                      8443    Service   Closed               false  false    false    false    NoPQC                       6m
```

### What the Columns Mean

| Column | Description |
|--------|-------------|
| **COMPLIANCE** | Overall status: Compliant, NonCompliant, Closed, Timeout, NoTLS, etc. |
| **GRADE** | Cipher strength grade (A-F). A = strong ciphers only. |
| **FS** | Forward secrecy: true if all negotiated ciphers use ephemeral key exchange (ECDHE/DHE). |
| **TLS1.3/1.2/1.0** | Whether each TLS version is supported. SSL3.0 appears in wide output (`kubectl get tlsreport -o wide`). |
| **PQC** | Post-quantum cryptography readiness (hybrid ML-KEM). See [Post-Quantum / ML-KEM](pqc-mlkem.md) for details. |
| **CERTEXPIRY** | Days until certificate expiration. |
| **SOURCE** | How the endpoint was discovered: Service, Ingress, Route, Pod, HTTPRoute, TLSRoute, Gateway, or Target. |

## Detailed Report

Use `describe` to see the full report for an endpoint:

```bash
$ kubectl describe tlsreport google-com-443-01d44386
```

Key sections in the output:

**Spec** — the endpoint being scanned:

```
Spec:
  Host:              google.com
  Port:              443
  Source Kind:       Target
  Source Name:       google-tls
```

**TLS Versions** — which versions the endpoint accepts:

```
Tls Versions:
  tls10:  true
  tls11:  true
  tls12:  true
  tls13:  true
```

**Cipher Suites** — negotiated ciphers per TLS version with strength grades:

```
Cipher Suites:
  TLS 1.0:
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  TLS 1.2:
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  TLS 1.3:
    TLS_AES_128_GCM_SHA256

Cipher Strength Grades:
  TLS_AES_128_GCM_SHA256:                   A
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:     B
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:  A

Overall Cipher Grade:  B
```

**Certificate Info** — issuer, subject, expiration, and public key details:

```
Certificate:
  Issuer:            CN=WR2,O=Google Trust Services,C=US
  Subject:           CN=*.google.com
  Not Before:        2026-01-20 08:39:19 UTC
  Not After:         2026-04-20 08:39:19 UTC
  Days Until Expiry: 53
  Is Expired:        false
  Hostname Match:    true
  Public Key:        ECDSA (256 bits)
  Signature Alg:     ECDSA-SHA256
  Chain Length:       3
  DNS Names:         *.google.com, google.com
  Serial:            a1b2c3
  Fingerprint:       4b5c6d... (SHA-256 of the DER certificate)
  IP SANs:           203.0.113.10
```

**Forward Secrecy and Key Exchange:**

```
Compliance:
  Forward Secrecy: true

Key Exchange Types:
  TLS 1.2: ECDHE
  TLS 1.3: TLS13
```

**ALPN Protocols** — negotiated application-layer protocol per TLS version:

```
ALPN Protocols:
  TLS 1.2: h2
  TLS 1.3: h2
```

**Post-Quantum Readiness** — key exchange curves and PQC classification
(see [Post-Quantum / ML-KEM](pqc-mlkem.md) for full details):

```
Negotiated Curves:
  TLS 1.2:  X25519
  TLS 1.3:  X25519MLKEM768
Quantum Ready:      true
ML-KEM Supported:   true
PQC Readiness:      PQCReady
```

**Scan Info** — timing and retry state:

```
Scan Info:
  Last Check:         2026-07-15 10:30:00 UTC
  Check Count:        12
  Scan Duration:      1.23s
  Consecutive Errors: 0
```

**OpenShift TLS Profile Compliance** (OpenShift clusters only):

```
API Server Profile Compliance:
  Compliant:            true
  Min TLS Version Met:  true
  Profile Type:         Intermediate
```

**Conditions** — status conditions for programmatic access:

```
Conditions:
  Type: TLSCompliant      Status: True   Message: Endpoint supports modern TLS (1.2 or 1.3)
  Type: CertificateValid  Status: True   Message: TLS certificate is valid for 53 more days
  Type: PQCCompliant      Status: True   Message: Endpoint supports TLS 1.3 with hybrid ML-KEM key exchange (verified by active probe)
```

## Filtering Reports

Find non-compliant endpoints:

```bash
kubectl get tlsreport -o json | \
  jq '.items[] | select(.status.complianceStatus == "NonCompliant") | .metadata.name'
```

Find endpoints with expiring certificates (< 30 days):

```bash
kubectl get tlsreport -o json | \
  jq '.items[] | select(.status.certificateInfo.daysUntilExpiry < 30) | {name: .metadata.name, host: .spec.host, days: .status.certificateInfo.daysUntilExpiry}'
```

Filter by source type:

```bash
kubectl get tlsreport -o json | \
  jq '.items[] | select(.spec.sourceKind == "Route") | .metadata.name'
```

Find hostNetwork pod endpoints:

```bash
kubectl get tlsreport -l tls-compliance.telco.openshift.io/host-network=true
```

## Kubernetes Events

The operator emits events on each report. View them with:

```bash
$ kubectl describe tlsreport rhcos4-moderate-master-rs-openshift-compliance-8443-03744f25
...
Events:
  Type     Reason               Age   From                       Message
  ----     ------               ----  ----                       -------
  Normal   EndpointDiscovered   10m   tls-compliance-controller  Discovered TLS endpoint rhcos4-moderate-master-rs.openshift-compliance:8443 from Service openshift-compliance/rhcos4-moderate-master-rs
  Warning  ComplianceChanged    9m    tls-compliance-controller  Compliance status changed from Timeout to Compliant for rhcos4-moderate-master-rs.openshift-compliance:8443
  Warning  CertificateExpiring  9m    tls-compliance-controller  TLS certificate for rhcos4-moderate-master-rs.openshift-compliance:8443 expires in 0 days
```

Or query events cluster-wide by reason:

```bash
kubectl get events --field-selector reason=ComplianceChanged
kubectl get events --field-selector reason=CertificateExpiring
```

---

Next: [Custom Targets](custom-targets.md)
