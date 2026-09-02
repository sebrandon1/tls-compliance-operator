#!/usr/bin/env bash
# Run govulncheck with .govulncheckignore filtering.
set -euo pipefail

GOVULNCHECK="${1:-govulncheck}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IGNORE_FILE="${ROOT}/.govulncheckignore"
OUTPUT_FILE=$(mktemp)

trap 'rm -f "${OUTPUT_FILE}"' EXIT

echo "Running ${GOVULNCHECK} -show verbose ./..."

# Run govulncheck and capture output.
set +e
"${GOVULNCHECK}" -show verbose ./... > "${OUTPUT_FILE}" 2>&1
EXIT_CODE=$?
set -e

# Extract all GO- identifiers from output (findings)
FINDINGS=$(grep -oE 'GO-[0-9]{4}-[0-9]+' "${OUTPUT_FILE}" | sort -u || true)

if [ -z "${FINDINGS}" ]; then
    if [ $EXIT_CODE -eq 0 ]; then
        cat "${OUTPUT_FILE}"
        echo "govulncheck passed (no findings)"
        exit 0
    else
        cat "${OUTPUT_FILE}"
        echo "govulncheck failed with exit code ${EXIT_CODE} but no GO- findings parsed"
        exit $EXIT_CODE
    fi
fi

# We have findings. Check against ignore file.
NON_IGNORED=()
while read -r id; do
    if [ -f "${IGNORE_FILE}" ] && grep -qx "${id}" "${IGNORE_FILE}"; then
        echo "Ignored: ${id}"
    else
        NON_IGNORED+=("${id}")
    fi
done <<< "${FINDINGS}"

if [ ${#NON_IGNORED[@]} -eq 0 ]; then
    cat "${OUTPUT_FILE}"
    echo "All govulncheck findings are in .govulncheckignore"
    exit 0
fi

# We have non-ignored findings.
cat "${OUTPUT_FILE}"
echo ""
echo "Non-ignored vulnerabilities found: ${NON_IGNORED[*]}"

if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::error::govulncheck found non-ignored vulnerabilities: ${NON_IGNORED[*]}"
fi

exit 1
