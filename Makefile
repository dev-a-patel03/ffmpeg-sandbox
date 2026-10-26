# Companion demo for Part 1. Builds the sandbox helper, probes, test harness, and
# Go worker into ./bin. The worker finds nonet/socket_probe beside itself; point
# it at ffmpeg/ffprobe with FFMPEG=/path FFPROBE=/path (9.0.2 recommended).

CC      ?= gcc
CFLAGS  ?= -O2 -static -Wall
GO      ?= go
BIN     := bin

CBINS := $(BIN)/nonet $(BIN)/socket_probe $(BIN)/bypass_test $(BIN)/fork_test $(BIN)/dumpable_proof $(BIN)/fd_probe
CSRCS := sandbox/nonet.c sandbox/socket_probe.c test/bypass_test.c test/fork_test.c test/fd_probe.c test/dumpable_proof.c

.PHONY: all build worker selftest isolation proofs fdtest strict docker clean
all: build
build: $(CBINS) $(BIN)/worker

$(BIN):
	mkdir -p $(BIN)

$(BIN)/nonet: sandbox/nonet.c | $(BIN)
	$(CC) $(CFLAGS) $< -o $@

$(BIN)/socket_probe: sandbox/socket_probe.c | $(BIN)
	$(CC) $(CFLAGS) $< -o $@

$(BIN)/bypass_test: test/bypass_test.c | $(BIN)
	$(CC) $(CFLAGS) $< -o $@

$(BIN)/fork_test: test/fork_test.c | $(BIN)
	$(CC) $(CFLAGS) -pthread $< -o $@

$(BIN)/fd_probe: test/fd_probe.c | $(BIN)
	$(CC) $(CFLAGS) $< -o $@

# dumpable_proof opens /proc; no need for a static build.
$(BIN)/dumpable_proof: test/dumpable_proof.c | $(BIN)
	$(CC) -O2 -Wall $< -o $@

$(BIN)/worker: worker/*.go | $(BIN)
	cd worker && $(GO) build -o ../$(BIN)/worker .

worker: $(BIN)/worker

selftest: build
	./$(BIN)/worker selftest

isolation: build
	./test/isolation.sh
	./test/fd_test.sh

fdtest: build
	./test/fd_test.sh

# Strict compile of every C source; catches the missing-_GNU_SOURCE implicit-decl class.
strict:
	@for f in $(CSRCS); do \
	  echo "strict: $$f"; \
	  $(CC) -std=c11 -Wall -Wextra -Werror -c $$f -o /dev/null || exit 1; \
	done
	@echo "strict: all C sources clean under -std=c11 -Wall -Wextra -Werror"

proofs: build
	@echo "== dumpable (expect: child reads bytes) =="  ; ./$(BIN)/dumpable_proof dumpable
	@echo "== nondumpable (expect: Permission denied) ="; ./$(BIN)/dumpable_proof nondumpable
	@echo "== max_pixels exit code =="                  ; ./test/exit_code_test.sh

docker:
	docker build -t ffmpeg-sandbox-demo .

clean:
	rm -rf $(BIN)
