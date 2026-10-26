# Threat model

The matrix from the article, with the demo command that exercises each row.
Three layers stack: input limits (FFmpeg's flags and the probe's checks), the OS
sandbox, and the network cage. Read each row per stage: the worker relies on Layers 1
and 2, the probe on Layers 1 and 3.

| Threat | Layer 1: input limits | Layer 2: OS sandbox | Layer 3: network cage (probe) | Demo |
|---|---|---|---|---|
| Disguised playlists (HLS/concat SSRF/LFI) | `-format_whitelist` blocks hls/concat demuxers | no host bind mounts; `file://` can't reach host | egress to S3 only | `worker probe` on a `.m3u8`/`.png` → Rejected |
| Unknown demuxer 0-days (e.g. CVE-2026-39210) | none (mpegts is an accepted format, so the demuxer still runs) | `nonet` blocks `socket()`, `socketpair()`, `io_uring` and process creation, denies foreign ABIs | egress to S3 only, DNS allow-list | `make isolation` |
| Decompression bombs / resource exhaustion | `-max_pixels 9437184`, `-max_alloc`, `-max_streams 33` with a reject above 32 | the container's CPU and memory limits (the ECS task size; this repo sets none) | n/a | `worker probe` on 8K → Rejected; `make proofs` |
| A codec the build lacks | the probe checks the codec of each stream the worker decodes against one table | n/a | n/a | `worker probe` with `FFPROBE` set to a minimal build (not shipped here) on an MP2 or ProRes file → Rejected |
| Credential theft via `/proc` | n/a | `nonet` + `PR_SET_DUMPABLE(0)` | the probe's role holds no S3 permission; S3-only egress; DNS Firewall | `dumpable_proof`; `test/envtest.sh` |
| A hijacked tool outliving its job (`setsid` child) | n/a | `nonet` denies process creation; as a backstop the worker, a child subreaper, kills leftovers after each tool and fails the run as hostile | a leftover makes the probe `Probe.Rejected`; Lambda refuses the subreaper, so the probe resets the environment (`ShouldExit`) to clear an orphan it cannot reap | `make isolation`; a fake `FFPROBE` that runs `setsid sleep 30 &` → `Probe.Rejected` |

Layer 3 is for the probe Lambda, whose parser keeps the network. The worker has
network too, for S3 and SQS, but its parsers don't. Layer 2 takes the socket away
from them.

## Why `nonet` is the load-bearing control

Clearing the child's environment does not help on its own: a same-uid child
reads PID 1's environment straight out of `/proc/1/environ` (run
`test/envtest.sh` with the Docker command in its header). Even a leaked
credential URI is useless without a socket to `169.254.170.2`. So the control
that matters most is that the media tools are physically unable to open a socket.

The worker also marks itself non-dumpable (`PR_SET_DUMPABLE(0)`), which shuts
the `/proc` reads of its environment and its memory as long as the worker is
PID 1, and starts the media tools with an empty environment. The memory read
matters most, because the AWS SDK caches the real keys there, and keys need no
socket. Non-dumpable also stops a tool copying the worker's open sockets with
`pidfd_getfd`. A hijacked tool can still write what it reads into the output
video, which reaches the uploader and, through the CDN, every viewer. With an init process in front
(`docker run --init`, or ECS `initProcessEnabled`), PID 1 is the init, which
holds the same environment and stays dumpable, so the read works again. The same
goes for any sidecar sharing the PID namespace (`pidMode: task`).

## What the demo does and does not prove

Verified locally on the host; the socket results also reproduce in the hardened
container (the Docker commands are in the README):

- Under `nonet`, every socket family and `socketpair()` return EACCES, and the
  i386 `int 0x80`, x32, and `io_uring_setup` paths are denied.
- Under `nonet`, `fork`, `vfork`, `clone`, `clone3` and `posix_spawn` fail, and
  threads still start.
- ffmpeg, ffprobe, and a sample job through the real transcode path run fine
  under `nonet`; the sandbox does not break the tools.
- A process left behind fails the run as hostile input and is killed. Under
  `nonet` the fork itself fails, so the demo shows it on the probe, which runs
  without `nonet`.
- `max_pixels` makes an over-cap decode exit 234 with no output. The "rc=0" you
  may see is a shell pipeline artifact (`head`'s exit code), not ffmpeg's.
- `PR_SET_DUMPABLE(0)` blocks a same-uid child from reading the parent's environ.

Not exercised here (no AWS): the Lambda network controls, the gate Lambda and the
probe's Lambda environment reset (`ShouldExit`). The local `probe` leftover kill is
exercised (the `setsid` row above); only the Lambda-only reset is not.
Those are documented in [`../deploy/AWS-CONTROLS.md`](../deploy/AWS-CONTROLS.md)
and rest on AWS service behavior, not on code in this repo.

## Note on the baseline `io_uring` result

`make isolation` runs on the host, where there is no Docker default seccomp
profile, so the baseline shows `io_uring_setup: OPENED`. Inside the container,
Docker's default profile already blocks `io_uring_setup`, so the baseline there
shows "Operation not permitted". Under `nonet` both collapse to "Permission
denied". The article's before/after output is the in-container run.
