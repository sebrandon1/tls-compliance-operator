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
  port: 443
```

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
`TLSComplianceReport`:

```bash
$ kubectl get tlsreport | grep google
google-com-443-01d44386   google.com   443   Target   Compliant   B   true   true   true   true   53   72s
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

A validating admission webhook enforces the following rules on create and
update:

- **Host format** — must be a valid IP address or DNS name (RFC 1123 subdomain).
  Wildcards (`*`) are not allowed.
- **No duplicates** — two `TLSComplianceTarget` resources cannot specify the
  same host:port combination.

Example error for an invalid host:

```
The TLSComplianceTarget "bad-target" is invalid:
  spec.host: Invalid value: "*.example.com": wildcards are not allowed
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
