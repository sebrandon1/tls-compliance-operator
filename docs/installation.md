# Installation

## One-Command Deploy

Apply the latest release manifest directly to your cluster:

```bash
kubectl apply -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

This creates:
- `tls-compliance-operator-system` namespace
- `TLSComplianceReport` and `TLSComplianceTarget` CRDs
- Controller deployment with RBAC, metrics service, and PodDisruptionBudget

## Verify the Deployment

```bash
$ kubectl get pods -n tls-compliance-operator-system
NAME                                                          READY   STATUS    RESTARTS   AGE
tls-compliance-operator-controller-manager-5874cc68b4-x4dqk   1/1     Running   0          25s
```

The operator begins scanning immediately. Within a few minutes you'll see
`TLSComplianceReport` resources appearing:

```bash
$ kubectl get tlsreport
NAME                                                              HOST                                        PORT    SOURCE    COMPLIANCE   GRADE   TLS1.3   TLS1.2   TLS1.0   PQC            CERTEXPIRY   AGE
kubernetes-default-443-d74c551f                                   kubernetes.default                           443     Service   Compliant    A       true     true     false    TLS13Capable   365d         5m
console-openshift-console-apps-crc-testing-443-40b31eb3           console-openshift-console.apps-crc.testing   443     Route     Compliant    A       true     true     false    TLS13Capable   29d          5m
```

## OpenShift Notes

On OpenShift, you may need to grant a Security Context Constraint to the
operator's service account:

```bash
oc adm policy add-scc-to-user privileged \
  -z tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system
```

Then restart the deployment:

```bash
oc rollout restart deployment/tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system
```

The operator auto-detects optional APIs at startup and enables monitoring for
each:

```
INFO  setup  OpenShift Route API detected, enabling Route monitoring
INFO  setup  OpenShift Config API detected, enabling TLS security profile monitoring
INFO  setup  Gateway API resource detected  {"kind": "HTTPRoute"}
INFO  setup  Gateway API resource detected  {"kind": "TLSRoute"}
INFO  setup  Gateway API resource detected  {"kind": "Gateway"}
```

If Gateway API CRDs are not installed, the operator logs a skip message and
continues without them:

```
INFO  setup  Gateway API not detected, skipping Gateway resource monitoring
```

## Uninstall

```bash
kubectl delete -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

---

Next: [Viewing Reports](viewing-reports.md)
