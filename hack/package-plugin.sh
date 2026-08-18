#!/usr/bin/env bash
# Pack kubectl-tlsreport + LICENSE into a Krew-compatible tar.gz.
# Archives are deterministic (uid/gid 0, mtime 0) so sha256 is stable.
#
# Usage: package-plugin.sh <binary> <output.tar.gz>
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <binary> <output.tar.gz>" >&2
  exit 1
fi

BINARY=$1
OUTPUT=$2

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LICENSE="${ROOT}/LICENSE"

if [[ ! -f "${BINARY}" ]]; then
  echo "error: binary not found: ${BINARY}" >&2
  exit 1
fi
if [[ ! -f "${LICENSE}" ]]; then
  echo "error: LICENSE not found: ${LICENSE}" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT}")"

python3 - "${BINARY}" "${LICENSE}" "${OUTPUT}" <<'PY'
import gzip
import io
import sys
import tarfile
from pathlib import Path

binary, license_path, output = sys.argv[1:]

def add(tar: tarfile.TarFile, arcname: str, path: str, mode: int) -> None:
    data = Path(path).read_bytes()
    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    info.mtime = 0
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info, io.BytesIO(data))

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
    add(tar, "kubectl-tlsreport", binary, 0o755)
    add(tar, "LICENSE", license_path, 0o644)

with gzip.GzipFile(filename="", fileobj=open(output, "wb"), mode="wb", mtime=0) as gz:
    gz.write(buf.getvalue())
PY
