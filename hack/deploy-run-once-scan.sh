#!/usr/bin/env bash
# Deploy a run-once TLS compliance scan Job to the current cluster,
# wait for results, copy them locally, and clean up.
#
# Configurable via environment or Make variables:
#   IMG              - operator image (default: quay.io/bapalm/tls-compliance-operator:latest)
#   SCAN_NAMESPACE   - namespace for the Job (default: tls-compliance-scan)
#   SCAN_FORMAT      - output format: csv|json|yaml|junit|markdown|html|sarif (default: junit)
#   SCAN_FILE        - local path for results (default: results.xml)
#   SCAN_NAMESPACES  - comma-separated namespaces to scan (default: all)
#   EXTRA_ARGS       - additional manager flags, space separated
#                      (e.g. "--require-pqc --expected-groups X25519MLKEM768")
#   KEEPER_IMAGE     - sidecar image that keeps the pod alive after the scan so
#                      the results file can be copied out. Override for
#                      air-gapped clusters.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMG="${IMG:-quay.io/bapalm/tls-compliance-operator:latest}"
SCAN_NAMESPACE="${SCAN_NAMESPACE:-tls-compliance-scan}"
SCAN_FORMAT="${SCAN_FORMAT:-junit}"
SCAN_FILE="${SCAN_FILE:-results.xml}"
SCAN_NAMESPACES="${SCAN_NAMESPACES:-}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
KEEPER_IMAGE="${KEEPER_IMAGE:-registry.access.redhat.com/ubi9/ubi-minimal:latest}"
KUBECTL="${KUBECTL:-kubectl}"

JOB_NAME="tls-compliance-scan"
SA_NAME="tco-scanner"
ROLE_NAME="tco-scanner-role"
BINDING_NAME="tco-scanner-binding"
SCAN_TIMEOUT_SECONDS="${SCAN_TIMEOUT_SECONDS:-600}"

cleanup() {
  echo "Cleaning up..."
  ${KUBECTL} delete job "${JOB_NAME}" -n "${SCAN_NAMESPACE}" --ignore-not-found=true || true
  ${KUBECTL} delete clusterrolebinding "${BINDING_NAME}" --ignore-not-found=true || true
  ${KUBECTL} delete clusterrole "${ROLE_NAME}" --ignore-not-found=true || true
  ${KUBECTL} delete namespace "${SCAN_NAMESPACE}" --ignore-not-found=true || true
}
trap cleanup EXIT

echo "==> Creating namespace and RBAC..."
# A previous run's namespace may still be terminating; creating objects in it
# fails with "unable to create new content in namespace ... being terminated".
if [[ "$(${KUBECTL} get namespace "${SCAN_NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || true)" == "Terminating" ]]; then
  echo "==> Waiting for namespace ${SCAN_NAMESPACE} to finish terminating..."
  ${KUBECTL} wait --for=delete namespace/"${SCAN_NAMESPACE}" --timeout=300s 2>/dev/null || true
fi
${KUBECTL} create namespace "${SCAN_NAMESPACE}" --dry-run=client -o yaml | ${KUBECTL} apply -f -
${KUBECTL} create serviceaccount "${SA_NAME}" -n "${SCAN_NAMESPACE}" --dry-run=client -o yaml | ${KUBECTL} apply -f -

# The operator's generated ClusterRole is the single source of truth, applied
# under a scan-owned name so cleanup can remove it. Copying the rules by hand is
# what let them drift before.
sed "s/^  name: manager-role\$/  name: ${ROLE_NAME}/" "${REPO_ROOT}/config/rbac/role.yaml" |
  ${KUBECTL} apply -f -

${KUBECTL} create clusterrolebinding "${BINDING_NAME}" \
  --clusterrole="${ROLE_NAME}" \
  --serviceaccount="${SCAN_NAMESPACE}:${SA_NAME}" \
  --dry-run=client -o yaml | ${KUBECTL} apply -f -

if [[ -n "${SCAN_NAMESPACES}" ]]; then
  EXTRA_ARGS="${EXTRA_ARGS} --include-namespaces=${SCAN_NAMESPACES}"
fi

# One YAML list item per flag: a single scalar would be passed to the binary as
# one malformed argument.
ARGS_YAML=""
while IFS= read -r flag; do
  if [[ -n "${flag}" ]]; then
    ARGS_YAML="${ARGS_YAML}            - ${flag}"$'\n'
  fi
done < <(printf '%s\n' --run-once "--output-format=${SCAN_FORMAT}" --output-file=/results/report ${EXTRA_ARGS})

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
${ARGS_YAML}          volumeMounts:
            - name: results
              mountPath: /results
        # Retrieving the report needs a running container, so keep the pod alive
        # after the scan container exits; the emptyDir dies with the pod.
        - name: keeper
          image: ${KEEPER_IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sleep", "infinity"]
          volumeMounts:
            - name: results
              mountPath: /results
      volumes:
        - name: results
          emptyDir: {}
EOF

echo "==> Waiting for scan to complete..."
POD=""
for _ in $(seq 1 60); do
  POD=$(${KUBECTL} get pods -n "${SCAN_NAMESPACE}" \
    -l job-name="${JOB_NAME}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [[ -n "${POD}" ]] && break
  sleep 2
done
if [[ -z "${POD}" ]]; then
  echo "ERROR: scan pod never started." >&2
  exit 2
fi

EXIT_CODE=""
DEADLINE=$((SECONDS + SCAN_TIMEOUT_SECONDS))
while :; do
  EXIT_CODE=$(${KUBECTL} get pod "${POD}" -n "${SCAN_NAMESPACE}" -o jsonpath='{.status.containerStatuses[?(@.name=="scanner")].state.terminated.exitCode}' 2>/dev/null || true)
  [[ -n "${EXIT_CODE}" ]] && break
  if (( SECONDS >= DEADLINE )); then
    echo "ERROR: scan did not finish within ${SCAN_TIMEOUT_SECONDS}s." >&2
    ${KUBECTL} get pod "${POD}" -n "${SCAN_NAMESPACE}" -o wide >&2 || true
    exit 2
  fi
  sleep 5
done

# Plain `cat` rather than `kubectl cp`: cp shells out to `tar`, which minimal
# sidecar images do not carry. Every export format is text.
if ! ${KUBECTL} exec -n "${SCAN_NAMESPACE}" "${POD}" -c keeper -- cat /results/report > "${SCAN_FILE}"; then
  rm -f "${SCAN_FILE}"
  echo "ERROR: could not retrieve results from ${POD}:/results/report" >&2
  echo "==> Job logs:"
  ${KUBECTL} logs "${POD}" -n "${SCAN_NAMESPACE}" -c scanner --tail=50 2>/dev/null || true
  exit 2
fi

if [[ "${EXIT_CODE}" != "0" ]]; then
  echo "==> Job logs:"
  ${KUBECTL} logs "${POD}" -n "${SCAN_NAMESPACE}" -c scanner --tail=50 2>/dev/null || true
fi

echo "==> Results written to ${SCAN_FILE}"
echo "==> Scan exit code: ${EXIT_CODE}"
exit "${EXIT_CODE}"
