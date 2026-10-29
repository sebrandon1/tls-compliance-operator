# Custom Targets

The operator automatically discovers endpoints from Services, Ingresses, Routes,
and Pods. To scan an arbitrary host:port (external services, partner APIs, etc.),
create a `TLSComplianceTarget`.

## Create a Target

```yaml
apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceTarget
metadata:
  name: google-tls
spec:
  host: google.com
```

When the mutating admission webhook is enabled, an omitted `port` defaults to
443. Set `port` explicitly for non-HTTPS endpoints or when the webhook is not
configured.

Apply it:

```bash
kubectl apply -f - <<EOF
apiVersion: security.telco.openshift.io/v1alpha1
kind: TLSComplianceTarget
metadata:
  name: google-tls
spec:
  host: google.com
  port: 443
EOF
```

The operator picks it up within seconds and creates a corresponding
`TLSComplianceReport`. You can also create targets with the plugin:

```bash
kubectl tlsreport target create google.com 443
kubectl tlsreport target create google.com 443 --wait
```

```bash
$ kubectl get tlsreport | grep google
google-com-443-01d44386   google.com   443   Target   Compliant   B   true   true   true   true   PQCReady   53   72s
```

The `SOURCE` column shows `Target` to distinguish these from auto-discovered
endpoints.

## View the Report

```bash
$ kubectl describe tlsreport google-com-443-01d44386
...
Spec:
  Host:              google.com
  Port:              443
  Source Kind:       Target
  Source Name:       google-tls
  Source Namespace:  cluster-scoped
Status:
  Compliance Status:  Compliant
  Overall Cipher Grade:  B
  Quantum Ready:         true
  Tls Versions:
    tls10:  true
    tls11:  true
    tls12:  true
    tls13:  true
  Negotiated Curves:
    TLS 1.3:  X25519MLKEM768
  Certificate Info:
    Days Until Expiry:  53
    Issuer:      CN=WR2,O=Google Trust Services,C=US
    Subject:     CN=*.google.com
```

## Validation

Admission webhooks run on create and update. The mutating webhook defaults an
omitted port to 443. The validating webhook enforces the following rules:

- **Host format** — must be a valid IP address or DNS name (RFC 1123 subdomain).
  Wildcards (`*`) are not allowed.
- **No duplicates** — two `TLSComplianceTarget` resources cannot specify the
  same host:port combination.
- **SSRF protection** — the webhook blocks hosts that point to internal or
  reserved network ranges to prevent server-side request forgery.

Discovery applies the same reserved/internal host rules to ExternalName
Services, Ingress TLS hosts, Route hosts, and HTTPRoute/TLSRoute/GRPCRoute hostnames.
Those hosts are skipped rather than probed.

The controller re-checks each Target's host before probing, so the rules apply
even when the webhook is not installed. Hostnames are checked again at connect time:
if a Target or ExternalName hostname resolves to a blocked address (for
example `kubernetes.default.svc` or a wildcard DNS name such as
`169.254.169.254.nip.io`), the probe is refused. The report is then marked
`Unreachable` and its error names the blocked address.

### Blocked Host Categories

The following host categories are rejected:

| Category | Examples | Reason |
|----------|----------|--------|
| IPv4 loopback | `127.0.0.1`, `127.0.0.2` | Loopback addresses |
| IPv6 loopback | `::1` | Loopback address |
| RFC 1918 private | `10.0.0.1`, `172.16.0.1`, `192.168.1.1` | Private network ranges |
| Link-local / cloud metadata | `169.254.169.254`, `169.254.1.1` | Cloud metadata endpoints |
| IPv6 link-local | `fe80::1` | Link-local addresses |
| IPv6 ULA | `fd00::1` | Unique local addresses |
| Unspecified | `0.0.0.0` | Unspecified address |
| CGNAT (RFC 6598) | `100.100.100.200`, `100.64.0.1` | Shared address space (Alibaba Cloud metadata) |
| IETF protocol assignments | `192.0.0.192` | Special-purpose range (OCI metadata) |
| Benchmarking (RFC 2544) | `198.18.0.1` | Non-routable test range |
| Multicast / reserved | `224.0.0.1`, `240.0.0.1`, `255.255.255.255`, `ff02::1` | Multicast, Class E, and broadcast |
| NAT64 | `64:ff9b::a9fe:a9fe` | Can embed any IPv4 address, including metadata |
| `localhost` | `localhost`, `app.localhost` | Loopback hostnames |
| Cluster-internal DNS | `myapp.default.svc.cluster.local` | In-cluster service DNS |
| Cloud metadata hostnames | `metadata.google.internal`, `metadata`, `instance-data` | Cloud provider metadata |

Example error for an invalid host:

```
The TLSComplianceTarget "bad-target" is invalid:
  spec.host: Invalid value: "*.example.com": wildcards are not allowed
```

Example error for a blocked internal address:

```
The TLSComplianceTarget "ssrf-target" is invalid:
  spec.host: Invalid value: "169.254.169.254": internal or reserved address is not allowed
```

Example error for a duplicate host:port:

```
The TLSComplianceTarget "dup-target" is invalid:
  spec: Invalid value: "google.com:443": duplicate host:port — already defined in TLSComplianceTarget "google-tls"
```

## Delete a Target

Deleting the `TLSComplianceTarget` removes the associated report during the
next cleanup cycle (default 5 minutes):

```bash
kubectl delete tlscompliancetarget google-tls
```

## Use Cases

- Monitor external dependencies your services rely on
- Validate partner or vendor API TLS configurations
- Audit third-party endpoints for compliance requirements
- Track certificate expiration on external services

---

Next: [Exporting Reports](exporting-reports.md)
