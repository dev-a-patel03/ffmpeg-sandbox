// Command worker is a small local mimic of a sandboxed transcoding worker.
package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

func usage() {
	fmt.Print(`ffmpeg-sandbox worker (companion demo for Part 1)

usage:
  worker tools                    show which binaries were resolved
  worker selftest                 run the startup self-tests
  worker probe <file>             run the probe gate on a local file
  worker transcode <in> <outdir>  transcode <in> under nonet to a 720p rung

binary resolution, in order: the matching env var
($NONET, $SOCKET_PROBE, $FFMPEG, $FFPROBE, $PACKAGER), then $SANDBOX_BIN
(or the worker's own directory), then PATH.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// Non-dumpable makes /proc/<pid> root-owned, so a same-uid child can't read our environ or memory.
	if err := prctl(syscall.PR_SET_DUMPABLE, 0); err != nil {
		fmt.Fprintf(os.Stderr, "prctl(PR_SET_DUMPABLE): %v\n", err)
		os.Exit(1)
	}
	// Orphans reparent to the worker, not PID 1, so killLeftovers can find them.
	if err := prctl(prSetChildSubreaper, 1); err != nil {
		fmt.Fprintf(os.Stderr, "prctl(PR_SET_CHILD_SUBREAPER): %v\n", err)
		os.Exit(1)
	}
	t := discoverTools()
	ctx := context.Background()

	switch os.Args[1] {
	case "tools":
		t.report()

	case "selftest":
		t.report()
		fmt.Println("running preflight self-tests under nonet...")
		if err := runPreflightSelfTests(t); err != nil {
			fmt.Fprintf(os.Stderr, "PREFLIGHT FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("PREFLIGHT OK: tools run under nonet, smoke job completed, socket(), socketpair(), fork() and clone() denied (exit 42)")

	case "probe":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		if err := probeGate(ctx, t, os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "transcode":
		if len(os.Args) < 4 {
			usage()
			os.Exit(2)
		}
		res, err := transcode(ctx, t, os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "transcode: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("exit=%d ran=%v progress_end=%v out_time_us=%d output=%v (%s)\n",
			res.exitCode, res.ran, res.progressEnd, res.outTimeUS, res.outputOK, res.outputPath)
		fmt.Println("verdict:", res.verdict())
		if !res.success() {
			os.Exit(1)
		}

	default:
		usage()
		os.Exit(2)
	}
}
