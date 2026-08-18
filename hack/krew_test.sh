#!/usr/bin/env bash
# Validate Krew packaging and manifest generation (no Krew install required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

GEN="${ROOT}/hack/generate-krew-manifest.sh"
PKG="${ROOT}/hack/package-plugin.sh"

expect_fail() {
  local needle=$1
  shift
  if "$@" >/dev/null 2>"${TMP}/err"; then
    echo "error: expected failure for: $*" >&2
    exit 1
  fi
  if ! grep -q "${needle}" "${TMP}/err"; then
    echo "error: stderr missing '${needle}':" >&2
    cat "${TMP}/err" >&2
    exit 1
  fi
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

hex64() {
  printf "${1}%.0s" {1..64}
  echo
}

BIN="${TMP}/kubectl-tlsreport-linux-amd64"
echo 'fake-plugin-binary' > "${BIN}"
chmod +x "${BIN}"

expect_fail "usage:" "${PKG}"
expect_fail "usage:" "${PKG}" "${BIN}"
expect_fail "usage:" "${PKG}" "${BIN}" "${TMP}/out.tar.gz" extra
expect_fail "binary not found" "${PKG}" "${TMP}/missing-binary" "${TMP}/out.tar.gz"

ARCHIVE="${TMP}/nested/kubectl-tlsreport-linux-amd64.tar.gz"
"${PKG}" "${BIN}" "${ARCHIVE}"

python3 - "${ARCHIVE}" "${ROOT}/LICENSE" "${BIN}" <<'PY'
import sys
import tarfile
from pathlib import Path

archive, license_path, binary = sys.argv[1:]
with tarfile.open(archive, "r:gz") as tar:
    names = tar.getnames()
    if names != ["kubectl-tlsreport", "LICENSE"]:
        raise SystemExit(f"unexpected archive members: {names}")
    plugin = tar.getmember("kubectl-tlsreport")
    if plugin.mode & 0o111 == 0:
        raise SystemExit("kubectl-tlsreport in archive is not executable")
    got_license = tar.extractfile("LICENSE").read()
    want_license = Path(license_path).read_bytes()
    if got_license != want_license:
        raise SystemExit("LICENSE in archive does not match repo LICENSE")
    got_bin = tar.extractfile("kubectl-tlsreport").read()
    want_bin = Path(binary).read_bytes()
    if got_bin != want_bin:
        raise SystemExit("binary in archive does not match input")
PY

ARCHIVE2="${TMP}/kubectl-tlsreport-linux-amd64-2.tar.gz"
"${PKG}" "${BIN}" "${ARCHIVE2}"
sha1=$(file_sha256 "${ARCHIVE}")
sha2=$(file_sha256 "${ARCHIVE2}")
if [[ "${sha1}" != "${sha2}" ]]; then
  echo "error: package-plugin.sh is not deterministic" >&2
  exit 1
fi

SHA_A=$(hex64 a)
SHA_B=$(hex64 b)
SHA_C=$(hex64 c)
SHA_D=$(hex64 d)
SHA_ARGS=(
  --sha-linux-amd64 "${SHA_A}"
  --sha-linux-arm64 "${SHA_B}"
  --sha-darwin-amd64 "${SHA_C}"
  --sha-darwin-arm64 "${SHA_D}"
)

expect_fail "all four --sha" "${GEN}"
expect_fail "all four --sha" "${GEN}" --version v1.2.3
expect_fail "requires a value" "${GEN}" --version
expect_fail "unknown argument" "${GEN}" --version v1.2.3 --nope
expect_fail "unknown platform" "${GEN}" --version v1.2.3 --sha-windows-amd64 "${SHA_A}"
expect_fail "all four --sha" "${GEN}" --version v1.2.3 \
  --sha-linux-amd64 "${SHA_A}" \
  --sha-darwin-amd64 "${SHA_C}" \
  --sha-darwin-arm64 "${SHA_D}"
expect_fail "v-prefixed semver" "${GEN}" --version 1.2.3 "${SHA_ARGS[@]}"
expect_fail "v-prefixed semver" "${GEN}" --version vfoo "${SHA_ARGS[@]}"
expect_fail "64-char hex sha256" "${GEN}" --version v1.2.3 \
  --sha-linux-amd64 deadbeef \
  --sha-linux-arm64 "${SHA_B}" \
  --sha-darwin-amd64 "${SHA_C}" \
  --sha-darwin-arm64 "${SHA_D}"

OUT="${TMP}/nested-out/tlsreport.yaml"
"${GEN}" --version v1.2.3-rc.1 "${SHA_ARGS[@]}" --output "${OUT}"
if ! grep -q 'version: "v1.2.3-rc.1"' "${OUT}"; then
  echo "error: prerelease version not written" >&2
  exit 1
fi

"${GEN}" --version v1.2.3 "${SHA_ARGS[@]}" --output "${OUT}"
"${GEN}" --version v1.2.3 "${SHA_ARGS[@]}" > "${TMP}/stdout.yaml"
if ! cmp -s "${OUT}" "${TMP}/stdout.yaml"; then
  echo "error: --output and stdout manifests differ" >&2
  diff -u "${OUT}" "${TMP}/stdout.yaml" >&2 || true
  exit 1
fi

python3 - "${OUT}" "${SHA_A}" "${SHA_B}" "${SHA_C}" "${SHA_D}" <<'PY'
import sys

path, sha_a, sha_b, sha_c, sha_d = sys.argv[1:]
text = open(path).read()
required = [
    "apiVersion: krew.googlecontainertools.github.com/v1alpha2",
    "kind: Plugin",
    "name: tlsreport",
    'version: "v1.2.3"',
    "bin: kubectl-tlsreport",
    "os: linux",
    "os: darwin",
    "arch: amd64",
    "arch: arm64",
    "kubectl-tlsreport-linux-amd64.tar.gz",
    "kubectl-tlsreport-linux-arm64.tar.gz",
    "kubectl-tlsreport-darwin-amd64.tar.gz",
    "kubectl-tlsreport-darwin-arm64.tar.gz",
    sha_a,
    sha_b,
    sha_c,
    sha_d,
]
for item in required:
    if item not in text:
        raise SystemExit(f"manifest missing {item!r}")
if text.count("sha256:") != 4:
    raise SystemExit(f"expected 4 sha256 entries, got {text.count('sha256:')}")
if text.count("bin: kubectl-tlsreport") != 4:
    raise SystemExit("expected bin on each of 4 platforms")
PY

ARCHDIR="${TMP}/archives"
mkdir -p "${ARCHDIR}"
for p in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
  cp "${ARCHIVE}" "${ARCHDIR}/kubectl-tlsreport-${p}.tar.gz"
done
expect_fail "archive not found" "${GEN}" --version v1.2.3 --archive-dir "${TMP}/missing-dir"
"${GEN}" --version v9.9.9 --archive-dir "${ARCHDIR}" --output "${TMP}/from-dir.yaml"
if ! grep -q 'version: "v9.9.9"' "${TMP}/from-dir.yaml"; then
  echo "error: --archive-dir did not write version" >&2
  exit 1
fi
if ! grep -q "${sha1}" "${TMP}/from-dir.yaml"; then
  echo "error: --archive-dir manifest missing archive sha256" >&2
  exit 1
fi
if [[ "$(grep -c sha256: "${TMP}/from-dir.yaml")" -ne 4 ]]; then
  echo "error: --archive-dir did not emit 4 sha256 entries" >&2
  exit 1
fi

COMMITTED="${ROOT}/plugins/tlsreport.yaml"
COMMITTED_VERSION=$(sed -n 's/^  version: "\(.*\)"/\1/p' "${COMMITTED}")
regen_args=(--version "${COMMITTED_VERSION}")
while read -r plat sha; do
  regen_args+=("--sha-${plat}" "${sha}")
done < <(python3 - "${COMMITTED}" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
uris = re.findall(r"kubectl-tlsreport-([a-z0-9-]+)\.tar.gz", text)
shas = re.findall(r"sha256: ([0-9a-fA-F]{64})", text)
if len(uris) != 4 or len(shas) != 4:
    raise SystemExit(f"committed manifest parse failed: {uris} {shas}")
for plat, sha in zip(uris, shas):
    print(plat, sha)
PY
)
"${GEN}" "${regen_args[@]}" --output "${TMP}/committed-regen.yaml"
if ! cmp -s "${COMMITTED}" "${TMP}/committed-regen.yaml"; then
  echo "error: plugins/tlsreport.yaml is stale; regenerate with hack/generate-krew-manifest.sh" >&2
  diff -u "${COMMITTED}" "${TMP}/committed-regen.yaml" >&2 || true
  exit 1
fi

echo "krew packaging and manifest checks passed"
