#!/usr/bin/env bash
# isolation.sh: run the harnesses bare and under nonet; needs `make build` first.
set -u

here="$(cd "$(dirname "$0")/.." && pwd)"
bin="${SANDBOX_BIN:-$here/bin}"

find_tool() {
  if [ -x "$bin/$1" ]; then echo "$bin/$1"; return; fi
  command -v "$1" 2>/dev/null && return
  echo ""; return 1
}

NONET="$(find_tool nonet)"
BYPASS="$(find_tool bypass_test)"
FORK="$(find_tool fork_test)"

if [ -z "$NONET" ] || [ -z "$BYPASS" ] || [ -z "$FORK" ]; then
  echo "build first: make build  (need bin/nonet, bin/bypass_test and bin/fork_test)" >&2
  exit 1
fi

fail=0
# Sets $out to the sandboxed output.
side_by_side() {
  local name; name="$(basename "$1")"
  echo "=== baseline: ./$name (no helper) ==="
  "$1"
  echo
  echo "=== sandboxed: ./nonet ./$name ==="
  out="$("$NONET" "$1")" || { echo "FAIL: $name did not run under nonet"; fail=1; }
  echo "$out"
  echo
}

side_by_side "$BYPASS"
if [ -z "$out" ] || echo "$out" | grep -qv 'Permission denied$'; then
  echo "FAIL: every socket row must be 'Permission denied' under nonet"; fail=1
fi

side_by_side "$FORK"
if echo "$out" | grep -v '^pthread_create:' | grep -q 'STARTED'; then
  echo "FAIL: a process started under nonet"; fail=1
fi
if ! echo "$out" | grep -q '^pthread_create: *STARTED'; then
  echo "FAIL: threads must still start under nonet"; fail=1
fi

[ "$fail" = 0 ] && echo "PASS: under nonet every socket is denied, no process starts, threads still work"
exit "$fail"
