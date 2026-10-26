package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// runPreflightSelfTests is the startup gate. A broken or unrunnable check exits
// the container before it registers healthy.
func runPreflightSelfTests(t tools) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if t.nonet == "" {
		return errors.New("preflight: nonet helper not found (build it: make build)")
	}

	// 1. Each media binary must start under nonet (-version just proves it loads).
	for _, tool := range []struct{ name, path, flag string }{
		{"ffmpeg", t.ffmpeg, "-version"},
		{"ffprobe", t.ffprobe, "-version"},
	} {
		if tool.path == "" {
			return fmt.Errorf("preflight: %s not found", tool.name)
		}
		if err := t.nonetCommand(ctx, tool.path, tool.flag).Run(); err != nil {
			return fmt.Errorf("preflight: %s failed under nonet: %w", tool.name, err)
		}
	}
	if t.packager != "" {
		if err := t.nonetCommand(ctx, t.packager, "--version").Run(); err != nil {
			return fmt.Errorf("preflight: packager failed under nonet: %w", err)
		}
	} else {
		fmt.Println("  note: packager not found, skipping its checks (set PACKAGER to include it)")
	}

	// 2. A real job must complete, so a broken codec list or scratch mount fails at boot.
	if err := smokeJob(ctx, t); err != nil {
		return fmt.Errorf("preflight: smoke job failed: %w", err)
	}

	// 3. socket_probe must exit 42 (EACCES on all four calls). Anything else fails.
	if t.socketProbe == "" {
		return errors.New("preflight: socket_probe not found (build it: make build)")
	}
	const codeSocketDenied = 42
	err := t.nonetCommand(ctx, t.socketProbe).Run()
	if err == nil {
		return errors.New("preflight security violation: a socket or a process was created under nonet")
	}
	code, ok := exitCode(err)
	if !ok || code != codeSocketDenied {
		return fmt.Errorf("preflight: socket_probe did not confirm a seccomp denial (exit %d): %w", code, err)
	}

	if n, err := killLeftovers(); err != nil {
		return fmt.Errorf("preflight: %w", err)
	} else if n > 0 {
		return fmt.Errorf("preflight: tools left %d process(es) running", n)
	}
	return nil
}

// smokeJob transcodes a generated 1 s sample and packages it if packager is present.
func smokeJob(ctx context.Context, t tools) error {
	// Scratch goes to $TMPDIR. Under --read-only, /tmp is read-only, so the image
	// sets TMPDIR=/scratch (a writable tmpfs). Name that cause if the dir won't
	// open, rather than let it read as a sandbox failure.
	scratch, err := os.MkdirTemp("", "preflight-*")
	if err != nil {
		return fmt.Errorf("scratch dir not writable (point TMPDIR at a writable mount such as /scratch): %w", err)
	}
	defer os.RemoveAll(scratch)

	src := filepath.Join(scratch, "src.mp4")
	enc := t.nonetCommand(ctx, t.ffmpeg,
		"-nostdin", "-v", "error",
		"-f", "lavfi", "-i", "testsrc2=size=320x180:rate=15:duration=1",
		"-f", "lavfi", "-i", "sine=frequency=440:duration=1",
		"-c:v", "libx264", "-preset", "ultrafast",
		"-c:a", "aac",
		"-y", src,
	)
	if out, err := enc.CombinedOutput(); err != nil {
		return fmt.Errorf("smoke sample: %w: %s", err, out)
	}

	res, err := transcode(ctx, t, src, scratch)
	if err != nil {
		return fmt.Errorf("smoke transcode: %w", err)
	}
	if !res.success() {
		return fmt.Errorf("smoke transcode: %s", res.verdict())
	}

	if t.packager == "" {
		return nil
	}
	tmp := filepath.Join(scratch, "tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		return err
	}
	pkg := t.nonetCommand(ctx, t.packager,
		fmt.Sprintf("in=%s,stream=video,output=%s", res.outputPath, filepath.Join(scratch, "out.mp4")),
		"--temp_dir", tmp, // writable scratch, not read-only /tmp
	)
	if out, err := pkg.CombinedOutput(); err != nil {
		return fmt.Errorf("smoke package: %w: %s", err, out)
	}
	return nil
}
