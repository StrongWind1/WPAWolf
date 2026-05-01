#!/usr/bin/env bash
# audit_citations.sh -- verify every [hcxpcapngtool:NNNN] citation in the
# repo points at a real line in the vendored ref/hcxtools/hcxpcapngtool.c.
#
# Citations decorate the wpawolf source ("matches the upstream behaviour at
# hcxpcapngtool.c:2526") so a reviewer can cross-check correctness against
# the C reference. If a citation drifts (the upstream file gets updated but
# the citation is not), reviewers silently lose that signal: the line they
# look at no longer says what the citation claims. This script walks every
# citation, parses the line number(s), and asserts the referenced lines
# exist in ref/hcxtools/hcxpcapngtool.c.
#
# It is deliberately conservative: it checks that the cited region is
# in-bounds and non-empty. It does not try to validate the *meaning* of the
# citation (that would require natural-language understanding). A reviewer
# still has to manually verify that the cited C code actually says what
# the surrounding wpawolf comment claims.
#
# ref/ is local-only (gitignored) so this is a developer-side check, not a
# CI gate. Clone hcxtools >= 7.0.1 into ref/hcxtools/ to run it. When the
# vendored source is missing, the script prints a one-line skip notice and
# exits 0 so it can still be wired into top-level make targets.
#
# Run via `make audit-citations` or directly:
#   ./tools/audit_citations.sh
#
# Exits non-zero on any out-of-bounds or unparseable citation.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
ref_file="${repo_root}/ref/hcxtools/hcxpcapngtool.c"

if [[ ! -f "${ref_file}" ]]; then
  cat >&2 <<MSG
audit_citations: ref/hcxtools/hcxpcapngtool.c not found -- skipping audit.
                  ref/ is gitignored (developer-side only). To run the
                  audit locally:
                    git clone --depth 1 --branch 7.1.2 \\
                      https://github.com/ZerBea/hcxtools.git ref/hcxtools
                  Citations target hcxpcapngtool >= 7.0.1.
MSG
  exit 0
fi

ref_lines="$(wc -l < "${ref_file}")"
fail=0
total=0

# Recognised citation forms in the codebase:
#   [hcxpcapngtool:NNNN]
#   [hcxpcapngtool:NNNN-MMMM]
#   [hcxpcapngtool.c:NNNN]
#   [hcxpcapngtool.c:NNNN-MMMM]
# Anything else (e.g. textual annotations like "if(authlen != 0x5f) ...")
# is left to a human reviewer.

while IFS=: read -r file line citation; do
  total=$((total + 1))

  # Pull the numeric tail. Refuse to silently pass non-numeric tails -- those
  # are textual citations the reviewer has to walk by eye.
  tail="${citation#*:}"
  tail="${tail%]}"

  if ! [[ "${tail}" =~ ^[0-9]+(-[0-9]+)?$ ]]; then
    echo "  SKIP (textual): ${file}:${line}  ${citation}"
    continue
  fi

  start="${tail%-*}"
  end="${tail#*-}"

  if (( start < 1 || start > ref_lines )); then
    echo "  FAIL (start out of bounds): ${file}:${line}  ${citation}  (ref has ${ref_lines} lines)"
    fail=$((fail + 1))
    continue
  fi
  if (( end < start || end > ref_lines )); then
    echo "  FAIL (end out of bounds):   ${file}:${line}  ${citation}  (ref has ${ref_lines} lines)"
    fail=$((fail + 1))
    continue
  fi

  region="$(sed -n "${start},${end}p" "${ref_file}")"
  if [[ -z "${region// }" ]]; then
    echo "  FAIL (region is blank):     ${file}:${line}  ${citation}"
    fail=$((fail + 1))
    continue
  fi
done < <(grep -rEn '\[hcxpcapngtool[.:][^]]*\]' "${repo_root}/src" "${repo_root}/ARCHITECTURE.md" 2>/dev/null \
  | grep -oE '^[^:]+:[0-9]+:.*\[hcxpcapngtool[.:][^]]*\]' \
  | sed -E 's/^([^:]+):([0-9]+):.*(\[hcxpcapngtool[.:][^]]*\]).*$/\1:\2:\3/' \
  | sort -u)

# PRODUCTION_VERSION is the upstream Makefile's own version stamp. Read it
# straight out of the vendored Makefile rather than carrying a duplicate file
# in the repo (ref/ is gitignored anyway).
ref_version="$(grep -E '^PRODUCTION_VERSION' "${repo_root}/ref/hcxtools/Makefile" 2>/dev/null \
  | head -1 | sed -E 's/.*:= *//' | tr -d ' ')"
ref_version="${ref_version:-<unknown>}"
echo
echo "audit_citations: scanned ${total} citation(s) against ref/hcxtools/hcxpcapngtool.c"
echo "                  vendored hcxtools version: ${ref_version} (citations target >= 7.0.1)"

if (( fail > 0 )); then
  echo "audit_citations: ${fail} citation(s) reference invalid lines" >&2
  exit 1
fi

echo "audit_citations: all numeric citations are in-bounds in the vendored source"
