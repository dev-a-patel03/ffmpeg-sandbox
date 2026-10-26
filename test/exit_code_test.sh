#!/usr/bin/env bash
#
# The trap: at the end of a pipeline (`ffmpeg ... | head`), $? is head's exit code,
# always 0, so a max_pixels reject looks like a silent success. Measured without a
# pipe the real code is 234 with no output, and -xerror/-max_error_rate don't change
# it. A small frame with max_pixels set below it hits the same decoder path
# (ff_set_dimensions -> get_buffer failure) as an over-cap 8K upload.
set -u
FF=${FFMPEG:-ffmpeg}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# true exit code, no pipe
rc() { "$@" >"$work/ect.out" 2>&1; echo $?; }

"$FF" -hide_banner -v error -f lavfi -i testsrc2=size=256x256:rate=10:duration=1 \
      -c:v libx264 -preset ultrafast -y "$work"/ect_src.mp4
echo "made 256x256 (65536 px) h264 source"

echo "--- the bug: ffmpeg's code lost to head's in a pipeline"
"$FF" -hide_banner -v error -max_pixels 1000 -i "$work"/ect_src.mp4 -frames:v 1 -f null - 2>&1 | head -3
echo "piped rc=$?   <- this is head's exit code, always 0"

echo "--- measured correctly (no pipe):"
printf 'plain -frames:v 1 -f null : rc=%s\n' "$(rc "$FF" -hide_banner -v error -max_pixels 1000 -i "$work"/ect_src.mp4 -frames:v 1 -f null -)"
printf '+ -xerror                 : rc=%s\n' "$(rc "$FF" -hide_banner -v error -xerror -max_pixels 1000 -i "$work"/ect_src.mp4 -frames:v 1 -f null -)"
printf '+ -max_error_rate 0       : rc=%s\n' "$(rc "$FF" -hide_banner -v error -max_error_rate 0 -max_pixels 1000 -i "$work"/ect_src.mp4 -frames:v 1 -f null -)"

r=$(rc "$FF" -hide_banner -v error -max_pixels 1000 -i "$work"/ect_src.mp4 -c:v libx264 -y "$work"/ect_bad.mp4)
printf 'real output file          : rc=%s, output=%s\n' "$r" "$([ -f "$work"/ect_bad.mp4 ] && echo written || echo none)"

r=$(rc "$FF" -hide_banner -v error -i "$work"/ect_src.mp4 -c:v libx264 -y "$work"/ect_ok.mp4)
printf 'control (no max_pixels)   : rc=%s, output=%s\n' "$r" "$([ -f "$work"/ect_ok.mp4 ] && echo written || echo none)"

# Observed 2026-10-22:
#   piped rc=0
#   plain -frames:v 1 -f null : rc=234
#   + -xerror                 : rc=234
#   + -max_error_rate 0       : rc=234
#   real output file          : rc=234, output=none
#   control (no max_pixels)   : rc=0,   output=written
