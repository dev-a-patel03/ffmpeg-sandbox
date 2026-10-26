# Mirrors the ECS worker task profile from the article. Two stages: build the
# static helper, probes, and worker, then a minimal Alpine runtime. The runtime
# hardening (--read-only, --cap-drop ALL, non-root, no-new-privileges, no IPC) comes
# from the run flags, not from here, the way ECS applies it through the task definition;
# see README.md for the full docker run. nonet stacks its seccomp filter on top of
# Docker's default profile at runtime.

FROM golang:1.27-alpine AS build
RUN apk add --no-cache build-base linux-headers
WORKDIR /src
RUN mkdir -p /out
COPY sandbox/ sandbox/
COPY test/ test/
COPY worker/ worker/
RUN gcc -O2 -static -Wall sandbox/nonet.c        -o /out/nonet        && \
    gcc -O2 -static -Wall sandbox/socket_probe.c -o /out/socket_probe && \
    gcc -O2 -static -Wall test/bypass_test.c     -o /out/bypass_test
RUN cd worker && CGO_ENABLED=0 go build -o /out/worker .

FROM alpine:3.20
# Alpine's ffmpeg keeps the image self-contained. Production ships the pinned
# static 9.0.2 build instead (COPY it in and set FFMPEG/FFPROBE). Shaka Packager
# is not in apk; add it and set PACKAGER to include its checks.
RUN apk add --no-cache ffmpeg
COPY --from=build /out/nonet /out/socket_probe /out/bypass_test /out/worker /usr/local/bin/
RUN adduser -D -u 1000 worker
USER 1000:1000
ENV SANDBOX_BIN=/usr/local/bin
# Rootfs is read-only at runtime, so temp must land on the writable tmpfs at
# /scratch, not read-only /tmp.
ENV TMPDIR=/scratch
ENTRYPOINT ["worker"]
CMD ["selftest"]
