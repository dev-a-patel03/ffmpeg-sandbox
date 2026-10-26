#!/usr/bin/env bash
# One-shot local demo: build, then selftest, probe, transcode, isolation. No Docker
# or AWS. Uses ffmpeg/ffprobe from $FFMPEG/$FFPROBE or PATH (9.0.2 to match).
set -euo pipefail
cd "$(dirname "$0")/.."

: "${FFMPEG:=$(command -v ffmpeg || true)}"
: "${FFPROBE:=$(command -v ffprobe || true)}"
if [ -z "$FFMPEG" ] || [ -z "$FFPROBE" ]; then
  echo "need ffmpeg and ffprobe on PATH, or set FFMPEG=/path FFPROBE=/path" >&2
  exit 1
fi
export FFMPEG FFPROBE
echo "ffmpeg : $FFMPEG"
echo "ffprobe: $FFPROBE"
echo

make build
echo

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
clip="$work/in.mp4"
"$FFMPEG" -hide_banner -v error \
  -f lavfi -i testsrc2=size=1280x720:rate=25:duration=2 \
  -f lavfi -i sine=frequency=440:duration=2 \
  -c:v libx264 -preset ultrafast -c:a aac -y "$clip"

echo "== selftest ==";        ./bin/worker selftest
echo; echo "== probe (accept) =="; ./bin/worker probe "$clip"
echo; echo "== transcode ==";      ./bin/worker transcode "$clip" "$work/out"
echo; echo "== isolation ==";      ./test/isolation.sh
