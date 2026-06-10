#!/usr/bin/env bash
#
# audit_stats.sh -- drift gate between STATS.md (the banner contract) and the
# counters that actually exist in the code.
#
# Two directions:
#   1. Every public field of `Stats` (src/stats.rs) and `FragmentStats`
#      (src/store/fragments.rs) must be named in backticks somewhere in
#      STATS.md. Per-sink field families that STATS.md documents once per family
#      (`lines_*`, `dropped_*`, `path_*`, `reassoc_req_*`) are exempted by prefix.
#   2. Every `stats.<field>` reference in STATS.md or ARCHITECTURE.md must be a
#      real field -- catches a renamed or deleted counter leaving a stale
#      documentation reference behind.
#
# Wired into `make check-all` via the `audit-stats` target. Exits non-zero on
# any drift so CI fails before a stale contract lands.
set -euo pipefail

cd "$(dirname "$0")/.."

contract="STATS.md"
arch="ARCHITECTURE.md"
stats_src="src/stats.rs"
fragments_src="src/store/fragments.rs"

for f in "${contract}" "${stats_src}" "${fragments_src}"; do
  if [[ ! -f ${f} ]]; then
    echo "audit_stats: missing ${f}" >&2
    exit 1
  fi
done

fields_file="$(mktemp)"
trap 'rm -f "${fields_file}"' EXIT

# Public struct fields: `    pub <name>: <type>,` lines. `pub fn` does not match
# because the function name is not followed directly by a colon.
grep -hoE '^[[:space:]]*pub [a-z0-9_]+:' "${stats_src}" "${fragments_src}" \
  | awk '{print $2}' | tr -d ':' | sort -u > "${fields_file}"

fail=0

# --- Direction 1: every code field must be named in the contract ---
# Accepted forms: `field` or `stats.field` in backticks anywhere in STATS.md.
while IFS= read -r field; do
  case "${field}" in
    lines_* | dropped_* | path_* | reassoc_req_*) continue ;;
    *) ;;
  esac
  if ! grep -qE "\`(stats\.|fragment_stats\.)?${field}\`" "${contract}"; then
    echo "  UNDOCUMENTED: ${field} (exists in code, not named in ${contract})"
    fail=1
  fi
done < "${fields_file}"

# --- Direction 2: every `stats.<field>` doc reference must exist in code ---
# `stats.rs` is the source-file name, not a field reference.
refs="$(grep -hoE 'stats\.[a-z0-9_]+' "${contract}" "${arch}" | sort -u || true)"
while IFS= read -r ref; do
  # Skip source-file / script-name fragments, not field references.
  [[ -z ${ref} || ${ref} == "stats.rs" || ${ref} == "stats.sh" ]] && continue
  field="${ref#stats.}"
  if ! grep -qx "${field}" "${fields_file}"; then
    echo "  STALE DOC REF: ${ref} (referenced in docs, no such field)"
    fail=1
  fi
done <<< "${refs}"

field_count="$(wc -l < "${fields_file}")"
if [[ ${fail} -ne 0 ]]; then
  echo "audit_stats: FAIL -- ${contract} and the code disagree (see above)"
  exit 1
fi
echo "audit_stats: OK -- ${field_count} counter fields reconciled against ${contract}"
