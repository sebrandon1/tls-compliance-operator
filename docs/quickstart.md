# Quick Start

Deploy the operator, wait for the first scan, create an external target, and
export the results. This walkthrough takes a few minutes on a cluster with
outbound network access.

Details live in the linked guides — this page is only the path through them.

## Prerequisites

- Kubernetes v1.28+ or OpenShift 4.x
- `kubectl` (or `oc`) and cluster-admin privileges
- Optional: [Kind](https://kind.sigs.k8s.io/) for a local cluster

## 1. Deploy

Create a Kind cluster if you do not already have one:

```bash
kind create cluster --name tls-compliance
```

**Release manifest** (Kind, Kubernetes, or OpenShift):

```bash
kubectl apply -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

**From source** against the cluster in your current kubeconfig:

```bash
make deploy IMG=quay.io/bapalm/tls-compliance-operator:latest
```

On OpenShift, grant an SCC and restart the deployment:

```bash
oc adm policy add-scc-to-user privileged \
  -z tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system

oc rollout restart deployment/tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system
```

See [Installation](installation.md) for what the manifest creates and how
optional APIs (Routes, Gateway API) are detected.

Wait until the controller is Running:

```bash
kubectl rollout status deployment/tls-compliance-operator-controller-manager \
  -n tls-compliance-operator-system --timeout=120s
```

## 2. View the first scan

The operator starts scanning as soon as it is up. Services, Ingresses, Routes,
Gateway API resources, and Pods show up as `TLSComplianceReport` CRs within a
few minutes.

```bash
kubectl get tlsreport
```

Install the `kubectl-tlsreport` plugin if you do not already have it. Krew,
release binaries, and `make build-plugin` are in
[Exporting Reports](exporting-reports.md#install-the-plugin).

Then get an at-a-glance summary:

```bash
kubectl tlsreport summary
```

Column meanings and `describe` output are in [Viewing Reports](viewing-reports.md).

## 3. Scan an external host

Create a `TLSComplianceTarget` and wait for the probe:

```bash
kubectl tlsreport target create google.com 443 --wait
```

The matching report has `SOURCE` set to `Target`. Webhook validation and SSRF
rules are in [Custom Targets](custom-targets.md).

## 4. Export results

```bash
kubectl tlsreport csv > tls-reports.csv
kubectl tlsreport json > tls-reports.json
```

Filters, JUnit, and `--fail-on-non-compliant` are in
[Exporting Reports](exporting-reports.md) and
[CI/CD Integration](ci-integration.md).

## Uninstall

```bash
kubectl delete -f https://github.com/sebrandon1/tls-compliance-operator/releases/latest/download/install.yaml
```

If you deployed from source, use `make undeploy` instead.

---

Next: [Viewing Reports](viewing-reports.md)
