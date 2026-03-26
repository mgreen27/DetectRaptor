#!/usr/bin/env bash

set -euo pipefail

VELOCIRAPTOR_BIN="${1:-./velociraptor}"
SCAN_TARGET="${2:-${SCAN_TARGET:-./velociraptor.exe}}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN_FILE="${REPO_ROOT}/golden/validate_yara.json"
ACTUAL_FILE="$(mktemp)"
TEMP_RULES_DIR="$(mktemp -d)"
WINDOWS_RULES_FILE="${TEMP_RULES_DIR}/full_windows_file.yar"
LINUX_RULES_FILE="${TEMP_RULES_DIR}/full_linux_file.yar"
MACOS_RULES_FILE="${TEMP_RULES_DIR}/full_macos_file.yar"
SCAN_TARGET="$(cd "$(dirname "${SCAN_TARGET}")" && pwd)/$(basename "${SCAN_TARGET}")"

if [[ ! -x "${VELOCIRAPTOR_BIN}" ]]; then
  echo "Velociraptor binary is not executable: ${VELOCIRAPTOR_BIN}" >&2
  exit 1
fi

if [[ ! -f "${SCAN_TARGET}" ]]; then
  echo "Scan target does not exist: ${SCAN_TARGET}" >&2
  exit 1
fi

if [[ ! -f "${GOLDEN_FILE}" ]]; then
  echo "Golden file does not exist: ${GOLDEN_FILE}" >&2
  exit 1
fi

cleanup() {
  rm -f "${ACTUAL_FILE}"
  rm -rf "${TEMP_RULES_DIR}"
}

trap cleanup EXIT

run_query() {
  local query="$1"
  local output

  output="$("${VELOCIRAPTOR_BIN}" query --timeout=120 --format=json "${query}")"
  if [[ -z "${output}" ]]; then
    printf '[]'
  else
    printf '%s' "${output}"
  fi
}

print_rows() {
  local label="$1"
  local rows="$2"

  echo "=== ${label} ==="
  printf '%s\n\n' "${rows}"
}

gzip -dc "${REPO_ROOT}/yara/full_windows_file.yar.gz" > "${WINDOWS_RULES_FILE}"
gzip -dc "${REPO_ROOT}/yara/full_linux_file.yar.gz" > "${LINUX_RULES_FILE}"
gzip -dc "${REPO_ROOT}/yara/full_macos_file.yar.gz" > "${MACOS_RULES_FILE}"

WINDOWS_ROWS="$(run_query \
  "SELECT basename(path=FileName) as Filename FROM yara(rules=read_file(filename='${WINDOWS_RULES_FILE}', length=30000000), files='${WINDOWS_RULES_FILE}', number=10) LIMIT 1")"
print_rows "windows file bundle (scan target)" "${WINDOWS_ROWS}"

LINUX_ROWS="$(run_query \
  "SELECT basename(path=FileName) as Filename FROM yara(rules=read_file(filename='${LINUX_RULES_FILE}', length=30000000), files='${LINUX_RULES_FILE}', number=10) LIMIT 1")"
print_rows "linux file bundle" "${LINUX_ROWS}"

MACOS_ROWS="$(run_query \
  "SELECT basename(path=FileName) as Filename FROM yara(rules=read_file(filename='${MACOS_RULES_FILE}', length=30000000), files='${MACOS_RULES_FILE}', number=10) LIMIT 1")"
print_rows "macos file bundle" "${MACOS_ROWS}"

WINDOWS_PROCESS_ROWS="$(run_query \
  "SELECT basename(path=FileName) as Filename FROM yara(rules=read_file(filename='${REPO_ROOT}/yara/full_windows_process.yar', length=30000000), files='${REPO_ROOT}/yara/full_windows_process.yar', number=10) LIMIT 1")"
print_rows "windows process bundle" "${WINDOWS_PROCESS_ROWS}"

LINUX_PROCESS_ROWS="$(run_query \
  "SELECT basename(path=FileName) as Filename FROM yara(rules=read_file(filename='${REPO_ROOT}/yara/full_linux_process.yar', length=30000000), files='${REPO_ROOT}/yara/full_linux_process.yar', number=10) LIMIT 1")"
print_rows "linux process bundle" "${LINUX_PROCESS_ROWS}"

WEBSHELL_ROWS="$(run_query \
  "SELECT basename(path=FileName) as Filename FROM yara(rules=read_file(filename='${REPO_ROOT}/yara/webshells.yar', length=30000000), files='${REPO_ROOT}/yara/webshells.yar', number=10) LIMIT 1")"
print_rows "webshell bundle" "${WEBSHELL_ROWS}"

python3 - "${ACTUAL_FILE}" "${WINDOWS_ROWS}" "${LINUX_ROWS}" "${MACOS_ROWS}" "${WINDOWS_PROCESS_ROWS}" "${LINUX_PROCESS_ROWS}" "${WEBSHELL_ROWS}" <<'PY'
import json
import sys
from pathlib import Path

actual_file = Path(sys.argv[1])
payload = {
    "windows_file_bundle": json.loads(sys.argv[2]),
    "linux_file_bundle": json.loads(sys.argv[3]),
    "macos_file_bundle": json.loads(sys.argv[4]),
    "windows_process_bundle": json.loads(sys.argv[5]),
    "linux_process_bundle": json.loads(sys.argv[6]),
    "webshell_bundle": json.loads(sys.argv[7]),
}
actual_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

if ! diff -u "${GOLDEN_FILE}" "${ACTUAL_FILE}"; then
  echo "YARA validation did not match the golden file." >&2
  exit 1
fi

echo "YARA validation passed."
