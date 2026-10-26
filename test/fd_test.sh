#!/usr/bin/env bash
# fd_test.sh: prove nonet closes inherited fds above fd 3 and keeps fd 3 (the
# progress pipe). Opens fds 3,4,5 (bash leaves them inherited), runs fd_probe under
# nonet, checks 4 and 5 are gone and 3 survives. /dev/null stands in for a socket.
set -u

here="$(cd "$(dirname "$0")/.." && pwd)"
bin="${SANDBOX_BIN:-$here/bin}"
NONET="$bin/nonet"
PROBE="$bin/fd_probe"

if [ ! -x "$NONET" ] || [ ! -x "$PROBE" ]; then
  echo "build first: make build  (need bin/nonet and bin/fd_probe)" >&2
  exit 1
fi

exec 3>/dev/null 4>/dev/null 5>/dev/null
out="$("$NONET" "$PROBE")"
exec 3>&- 4>&- 5>&-

echo "$out"
fail=0
echo "$out" | grep -q "fd 3: open"   || { echo "FAIL: fd 3 (progress pipe) must be preserved"; fail=1; }
echo "$out" | grep -q "fd 4: closed" || { echo "FAIL: fd 4 must be closed by nonet";           fail=1; }
echo "$out" | grep -q "fd 5: closed" || { echo "FAIL: fd 5 must be closed by nonet";           fail=1; }
[ "$fail" = 0 ] && echo "PASS: nonet closed inherited fds >3 and kept fd 3"
exit "$fail"
