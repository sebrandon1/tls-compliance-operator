# Interoperability with imagecertinfo-operator

When both `tls-compliance-operator` and [`imagecertinfo-operator`](https://github.com/sebrandon1/imagecertinfo-operator) run on the same cluster, `TLSComplianceReport` objects for Pod sources are automatically enriched with Red Hat image certification data from the Pyxis API.

A single `kubectl get tlsreport <name> -o yaml` then surfaces both TLS posture **and** image certification posture together.

## Prerequisites

- `imagecertinfo-operator` is installed and its controller is running
- `imagecertinfo-operator` CRDs are installed (`ImageCertificationInfo`)
- The `tls-compliance-operator` service account has permission to list `ImageCertificationInfo` resources (see [RBAC Binding](#rbac-binding) below)

## RBAC Binding

The `imagecertinfo-operator` ships a viewer `ClusterRole` for its custom resource. Bind it to the `tls-compliance-operator` service account:

```bash
kubectl create clusterrolebinding imagecertinfo-viewer-for-tls-operator \
  --clusterrole=imagecertinfo-operator-imagecertificationinfo-viewer-role \
  --serviceaccount=tls-compliance-operator-system:tls-compliance-operator-controller-manager
```

Without this binding the enrichment is silently skipped and `status.imageCertificationInfo` remains empty.

## How It Works

1. When a `TLSComplianceReport` is created or updated for a `sourceKind: Pod` endpoint, the controller fetches the pod's `containerStatuses`.
2. For each container with a SHA-256 image digest, it looks up the matching `ImageCertificationInfo` CR using a digest label (`imagecertinfo.security.telco.openshift.io/digest`).
3. If a match is found, the certification data is written to `status.imageCertificationInfo`.

Only `sourceKind: Pod` reports are enriched. Service, Ingress, and custom-target reports are unaffected.

## `status.imageCertificationInfo` Field Reference

Each entry in `status.imageCertificationInfo` corresponds to one container in the pod:

| Field | Type | Description |
|-------|------|-------------|
| `containerName` | string | Container name within the pod |
| `imageRef` | string | Full image reference including digest |
| `iciName` | string | Name of the matching `ImageCertificationInfo` CR |
| `certificationStatus` | string | `Certified`, `NotCertified`, `Unknown`, or empty if not yet synced |
| `healthIndex` | string | Pyxis health grade: `A`–`F`, or empty |
| `criticalCveCount` | integer | Number of critical CVEs, or absent if no Pyxis data |
| `daysUntilEol` | integer | Days until end-of-life (negative = past EOL), or absent |
| `registryType` | string | `RedHat`, `Partner`, `Community`, or empty |

## Example

```bash
kubectl get tlsreport ptp-operator-pod-report -o yaml
```

```yaml
status:
  complianceStatus: Compliant
  imageCertificationInfo:
  - containerName: cloud-event-proxy
    imageRef: registry.redhat.io/openshift4/ose-cloud-event-proxy@sha256:abcdef...
    iciName: registry.redhat.io.openshift4.ose-cloud-event-proxy.abcdef12
    certificationStatus: Certified
    healthIndex: A
    criticalCveCount: 0
    daysUntilEol: 340
    registryType: RedHat
  tlsVersion: TLS 1.3
  ...
```

## Graceful Degradation

If `imagecertinfo-operator` is not installed:

- The `IsNoMatchError` check catches the missing CRD and skips enrichment silently
- `status.imageCertificationInfo` is omitted from the report
- No error conditions are set on the report
- No error logs are emitted (logged at V(1) only)

If `imagecertinfo-operator` is installed but an ICI CR has not been created yet (operator still syncing):

- The enrichment finds no matching CR and omits the entry
- On the next reconcile cycle the entry will appear once the ICI CR exists

## Troubleshooting

**`status.imageCertificationInfo` is empty:**

1. Verify the RBAC binding exists: `kubectl get clusterrolebinding imagecertinfo-viewer-for-tls-operator`
2. Verify the ICI CRD is installed: `kubectl get crd imagecertificationinfoes.security.telco.openshift.io`
3. Verify ICI CRs exist for the pod's images: `kubectl get imagecertificationinfoes`
4. Check that ICI CRs have the digest label: `kubectl get imagecertificationinfoes -o jsonpath='{range .items[*]}{.metadata.labels}{"\n"}{end}'`
5. Check the tls-compliance-operator logs for `enrichWithImageCertInfo` entries

**ICI CRs exist but have no Pyxis data:**

The ICI operator may still be syncing with Pyxis. `certificationStatus` will be empty until the first Pyxis query completes. `imageCertificationInfo` entries will still appear but with only `containerName`, `imageRef`, and `iciName` populated.
