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

## Install with OperatorHub

The operator is published to both OLM catalogs:

| Catalog | Audience | Listing |
|---------|----------|---------|
| [OperatorHub.io](https://operatorhub.io/operator/tls-compliance-operator) | Vanilla Kubernetes with OLM | [`k8s-operatorhub/community-operators`](https://github.com/k8s-operatorhub/community-operators/tree/main/operators/tls-compliance-operator) |
| OpenShift community catalog | OpenShift 4.20 and later | [`redhat-openshift-ecosystem/community-operators-prod`](https://github.com/redhat-openshift-ecosystem/community-operators-prod/tree/main/operators/tls-compliance-operator) |

Both catalogs publish the same versions on the `stable` channel, starting at
1.1.16. The operator declares `AllNamespaces` as its only install mode, so OLM
installs a single cluster-wide instance.

### OperatorHub.io

With [OLM installed](https://olm.operatorframework.io/docs/getting-started/),
create a `Subscription` in the `operators` namespace:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: tls-compliance-operator
  namespace: operators
spec:
  channel: stable
  name: tls-compliance-operator
  source: operatorhubio-catalog
  sourceNamespace: olm
```

```bash
kubectl apply -f tls-compliance-operator-subscription.yaml
```

### OpenShift

In the console, open **Operators → OperatorHub**, search for "TLS Compliance
Operator", accept the default `stable` channel, and install it into the
`openshift-operators` namespace (AllNamespaces). From the CLI:

```bash
cat <<'EOF' | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: tls-compliance-operator
  namespace: openshift-operators
spec:
  channel: stable
  name: tls-compliance-operator
  source: community-operators
  sourceNamespace: openshift-marketplace
EOF
```

OLM-managed installs do not create `tls-compliance-operator-system`; the CSV and
RBAC land in the operator's namespace instead. Use the
[one-command deploy](#one-command-deploy) if you want the standalone manifests
without OLM.

A newly published version becomes installable only after its bundle PR **and**
the follow-up catalog-update PR both merge. If the channel does not show the
version you expect, check the catalog source before assuming the release failed.

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
NAME                                                              HOST                                        PORT    SOURCE    COMPLIANCE   GRADE   FS     TLS1.3   TLS1.2   TLS1.0   PQC            CERTEXPIRY   AGE
kubernetes-default-443-d74c551f                                   kubernetes.default                           443     Service   Compliant    A       true   true     true     false    TLS13Capable   365          5m
console-openshift-console-apps-crc-testing-443-40b31eb3           console-openshift-console.apps-crc.testing   443     Route     Compliant    A       true   true     true     false    TLS13Capable   29           5m
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
INFO  setup  Gateway API resource detected  {"kind": "GRPCRoute"}
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

Next: [Quick Start](quickstart.md)
