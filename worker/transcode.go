package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type transcodeResult struct {
	exitCode    int
	ran         bool
	progressEnd bool
	outTimeUS   int64
	outputPath  string
	outputOK    bool
	scanErr     error // non-nil if reading the progress pipe failed
	leftovers   int
	timedOut    bool // the worker's deadline fired, so a 137 is its own kill
}

func (r *transcodeResult) success() bool {
	return r.ran && r.exitCode == 0 && r.outputOK && r.progressEnd && r.outTimeUS > 0 &&
		r.scanErr == nil && r.leftovers == 0
}

func (r *transcodeResult) verdict() string {
	switch {
	case r.success():
		return "SUCCESS"
	case r.leftovers > 0:
		return fmt.Sprintf("HOSTILE INPUT (ffmpeg left %d process(es) running; output discarded)", r.leftovers)
	case !r.ran:
		return "DID NOT RUN (killed before exit, or spawn failure)"
	case r.exitCode == 137 && r.timedOut:
		return "TIMED OUT (the worker killed ffmpeg at its deadline)"
	case r.exitCode == 137:
		return "KILLED (a SIGKILL the worker didn't send: OOM, or ffmpeg itself)"
	case r.exitCode == 8:
		return "FFMPEG USAGE ERROR (unknown option, filter, encoder or protocol)"
	case r.exitCode == 234:
		return "FFMPEG REFUSED INPUT OR ARGUMENT (exit 234: allow-list, max_pixels, bad filter argument)"
	case r.scanErr != nil:
		return fmt.Sprintf("PROGRESS READ ERROR (telemetry unreliable: %v)", r.scanErr)
	case r.exitCode == 0:
		return "EXIT 0 BUT INCOMPLETE (no progress=end, no output time, or no output: do not trust it)"
	default:
		return fmt.Sprintf("FAILED (exit %d)", r.exitCode)
	}
}

// transcode runs ffmpeg under nonet to a single 720p rung, reading -progress from
// fd 3. nonet closes only fds above 3 and execs ffmpeg in place, so the pipe's
// write end reaches ffmpeg as pipe:3.
func transcode(ctx context.Context, t tools, input, outDir string) (*transcodeResult, error) {
	if t.ffmpeg == "" {
		return nil, fmt.Errorf("ffmpeg not found")
	}
	if t.nonet == "" {
		return nil, fmt.Errorf("nonet not found (build it: make build)")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	out := filepath.Join(outDir, "out_720p.mp4")
	if err := os.Remove(out); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err // a stale output from an earlier run would read as outputOK
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	args := []string{"-nostdin", "-v", "error", "-progress", "pipe:3"}
	args = append(args, inputGuards("file,pipe")...)
	args = append(args,
		"-i", input,
		// V, not v, skips cover art; "?" allows a file with no audio.
		"-map", "0:V:0", "-map", "0:a:0?",
		"-vf", "scale=-2:720",
		"-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
		"-c:a", "aac", "-b:a", "128k",
		"-movflags", "+faststart",
		"-y", out,
	)
	cmd := t.nonetCommand(ctx, t.ffmpeg, args...)
	cmd.ExtraFiles = []*os.File{pw} // child fd 3

	res := &transcodeResult{outputPath: out}
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, err
	}
	pw.Close() // child now holds the only writer

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			switch k {
			case "progress":
				if v == "end" {
					res.progressEnd = true
				}
			case "out_time_us":
				if n, e := strconv.ParseInt(v, 10, 64); e == nil {
					res.outTimeUS = n
				}
			}
		}
		res.scanErr = sc.Err() // nil on a clean EOF
	}()

	werr := cmd.Wait()
	// Kill leftovers before the drain, since one may hold fd 3 open.
	leftovers, kerr := killLeftovers()
	// Drain before closing pr, or the final progress=end can be dropped. WaitDelay
	// doesn't cover ExtraFiles, so the read has its own deadline.
	pr.SetReadDeadline(time.Now().Add(waitDelay))
	<-done
	pr.Close()
	if kerr != nil || leftovers > 0 {
		os.Remove(out)
	}
	if kerr != nil {
		return nil, kerr
	}

	res.exitCode, res.ran = exitCode(werr)
	res.leftovers = leftovers
	res.timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if st, e := os.Stat(out); e == nil && st.Size() > 0 {
		res.outputOK = true
	}
	return res, nil
}
