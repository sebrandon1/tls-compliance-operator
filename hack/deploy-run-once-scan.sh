#!/usr/bin/env bash
# Deploy a run-once TLS compliance scan Job to the current cluster,
# wait for results, copy them locally, and clean up.
#
# Configurable via environment or Make variables:
#   IMG              - operator image (default: quay.io/bapalm/tls-compliance-operator:latest)
#   SCAN_NAMESPACE   - namespace for the Job (default: tls-compliance-scan)
#   SCAN_FORMAT      - output format: csv|json|yaml|junit|markdown (default: junit)
#   SCAN_FILE        - local path for results (default: results.xml)
#   SCAN_NAMESPACES  - comma-separated namespaces to scan (default: all)
set -euo pipefail

IMG="${IMG:-quay.io/bapalm/tls-compliance-operator:latest}"
SCAN_NAMESPACE="${SCAN_NAMESPACE:-tls-compliance-scan}"
SCAN_FORMAT="${SCAN_FORMAT:-junit}"
SCAN_FILE="${SCAN_FILE:-results.xml}"
SCAN_NAMESPACES="${SCAN_NAMESPACES:-}"
KUBECTL="${KUBECTL:-kubectl}"

JOB_NAME="tls-compliance-scan"
SA_NAME="tco-scanner"
ROLE_NAME="tco-scanner-role"
BINDING_NAME="tco-scanner-binding"

cleanup() {
  echo "Cleaning up..."
  ${KUBECTL} delete job "${JOB_NAME}" -n "${SCAN_NAMESPACE}" --ignore-not-found=true || true
  ${KUBECTL} delete clusterrolebinding "${BINDING_NAME}" --ignore-not-found=true || true
  ${KUBECTL} delete clusterrole "${ROLE_NAME}" --ignore-not-found=true || true
  ${KUBECTL} delete namespace "${SCAN_NAMESPACE}" --ignore-not-found=true || true
}
trap cleanup EXIT

echo "==> Creating namespace and RBAC..."
${KUBECTL} create namespace "${SCAN_NAMESPACE}" --dry-run=client -o yaml | ${KUBECTL} apply -f -
${KUBECTL} create serviceaccount "${SA_NAME}" -n "${SCAN_NAMESPACE}" --dry-run=client -o yaml | ${KUBECTL} apply -f -

# RBAC rules match config/rbac/role.yaml — update both when changing markers.
${KUBECTL} apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${ROLE_NAME}
rules:
  - apiGroups: [""]
    resources: [events]
    verbs: [create, patch]
  - apiGroups: [""]
    resources: [pods, services]
    verbs: [get, list, watch]
  - apiGroups: [config.openshift.io]
    resources: [apiservers]
    verbs: [get, list, watch]
  - apiGroups: [discovery.k8s.io]
    resources: [endpointslices]
    verbs: [get, list, watch]
  - apiGroups: [gateway.networking.k8s.io]
    resources: [gateways, httproutes, tlsroutes]
    verbs: [get, list, watch]
  - apiGroups: [machineconfiguration.openshift.io]
    resources: [kubeletconfigs]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [get, list, watch]
  - apiGroups: [operator.openshift.io]
    resources: [ingresscontrollers]
    verbs: [get, list, watch]
  - apiGroups: [route.openshift.io]
    resources: [routes]
    verbs: [get, list, watch]
  - apiGroups: [security.telco.openshift.io]
    resources: [tlscompliancereports]
    verbs: [create, delete, get, list, patch, update, watch]
  - apiGroups: [security.telco.openshift.io]
    resources: [tlscompliancereports/finalizers]
    verbs: [update]
  - apiGroups: [security.telco.openshift.io]
    resources: [tlscompliancereports/status, tlscompliancetargets/status]
    verbs: [get, patch, update]
  - apiGroups: [security.telco.openshift.io]
    resources: [tlscompliancetargets]
    verbs: [get, list, watch]
EOF

${KUBECTL} create clusterrolebinding "${BINDING_NAME}" \
  --clusterrole="${ROLE_NAME}" \
  --serviceaccount="${SCAN_NAMESPACE}:${SA_NAME}" \
  --dry-run=client -o yaml | ${KUBECTL} apply -f -

EXTRA_ARGS=""
if [[ -n "${SCAN_NAMESPACES}" ]]; then
  EXTRA_ARGS="--include-namespaces=${SCAN_NAMESPACES}"
fi

echo "==> Deploying scan Job (image: ${IMG})..."
${KUBECTL} apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
  namespace: ${SCAN_NAMESPACE}
spec:
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: ${SA_NAME}
      restartPolicy: Never
      containers:
        - name: scanner
          image: ${IMG}
          imagePullPolicy: Always
          args:
            - --run-once
            - --output-format=${SCAN_FORMAT}
            - --output-file=/results/report
            ${EXTRA_ARGS:+- ${EXTRA_ARGS}}
          volumeMounts:
            - name: results
              mountPath: /results
      volumes:
        - name: results
          emptyDir: {}
EOF

echo "==> Waiting for scan to complete..."
WAIT_FAILED=false
if ! ${KUBECTL} wait --for=condition=complete job/"${JOB_NAME}" \
    -n "${SCAN_NAMESPACE}" --timeout=600s 2>/dev/null; then
  WAIT_FAILED=true
fi

POD=$(${KUBECTL} get pods -n "${SCAN_NAMESPACE}" \
  -l job-name="${JOB_NAME}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ "${WAIT_FAILED}" == "true" ]]; then
  FAILED=$(${KUBECTL} get job "${JOB_NAME}" -n "${SCAN_NAMESPACE}" \
    -o jsonpath='{.status.failed}' 2>/dev/null || echo "0")
  FAILED="${FAILED:-0}"
  if [[ -n "${POD}" ]]; then
    echo "==> Job logs:"
    ${KUBECTL} logs "${POD}" -n "${SCAN_NAMESPACE}" --tail=50 2>/dev/null || true
  fi
  if [[ "${FAILED}" -gt 0 ]]; then
    echo "Scan found non-compliant endpoints (exit code 1)."
  else
    echo "ERROR: Scan timed out or failed to start."
    exit 2
  fi
fi

EXIT_CODE=0
if [[ -n "${POD}" ]]; then
  EXIT_CODE=$(${KUBECTL} get pod "${POD}" -n "${SCAN_NAMESPACE}" \
    -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || echo "2")
  if [[ -z "${EXIT_CODE}" ]]; then
    echo "ERROR: Container did not terminate."
    exit 2
  fi
  ${KUBECTL} cp "${SCAN_NAMESPACE}/${POD}:/results/report" "${SCAN_FILE}" 2>/dev/null || true
fi

if [[ -f "${SCAN_FILE}" ]]; then
  echo "==> Results written to ${SCAN_FILE}"
else
  echo "WARNING: Could not retrieve results file."
fi

echo "==> Scan exit code: ${EXIT_CODE}"
exit "${EXIT_CODE}"
