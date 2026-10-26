package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tools holds resolved binary paths; "" means not found, and callers decide
// whether that is fatal.
type tools struct {
	nonet       string
	socketProbe string
	ffmpeg      string
	ffprobe     string
	packager    string // optional; Shaka Packager may be absent
}

// locate resolves a binary by env var, then $SANDBOX_BIN (or the worker's dir),
// then PATH. A bare name in the env var resolves here, since nonet's execvp has no PATH.
func locate(name, envVar string) string {
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			if p, err := exec.LookPath(v); err == nil {
				return p
			}
			return v // fail on the path given rather than fall back
		}
	}
	binDir := os.Getenv("SANDBOX_BIN")
	if binDir == "" {
		if exe, err := os.Executable(); err == nil {
			binDir = filepath.Dir(exe)
		}
	}
	if binDir != "" {
		p := filepath.Join(binDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func discoverTools() tools {
	return tools{
		nonet:       locate("nonet", "NONET"),
		socketProbe: locate("socket_probe", "SOCKET_PROBE"),
		ffmpeg:      locate("ffmpeg", "FFMPEG"),
		ffprobe:     locate("ffprobe", "FFPROBE"),
		packager:    locate("packager", "PACKAGER"),
	}
}

func (t tools) report() {
	show := func(label, p string) {
		if p == "" {
			p = "(not found)"
		}
		fmt.Printf("  %-12s %s\n", label, p)
	}
	fmt.Println("resolved binaries:")
	show("nonet", t.nonet)
	show("socket_probe", t.socketProbe)
	show("ffmpeg", t.ffmpeg)
	show("ffprobe", t.ffprobe)
	show("packager", t.packager)
}

// groupKill puts cmd in its own process group and SIGKILLs the whole group on
// context cancel. nonet execs the tool in place, so the tool leads the group and
// the kill hits it, not the worker.
func groupKill(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return cmd.Process.Kill() // also reaches a tool that left its group
	}
	return cmd
}

const waitDelay = 5 * time.Second

// cmd builds a plain command, no nonet. The probe uses it because that stage
// needs the network. Env is empty, so pass scratch paths explicitly. WaitDelay
// doesn't cover ExtraFiles, so transcode bounds its fd 3 read itself.
func (t tools) cmd(ctx context.Context, bin string, args ...string) *exec.Cmd {
	c := groupKill(exec.CommandContext(ctx, bin, args...))
	c.Env = []string{} // non-nil, since a nil Env inherits the worker's
	c.WaitDelay = waitDelay
	return c
}

// nonetCommand builds a command that runs `tool args...` through nonet.
func (t tools) nonetCommand(ctx context.Context, tool string, args ...string) *exec.Cmd {
	return t.cmd(ctx, t.nonet, append([]string{tool}, args...)...)
}

const prSetChildSubreaper = 36

func prctl(option, arg uintptr) error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, option, arg, 0); errno != 0 {
		return errno
	}
	return nil
}

// killLeftovers SIGKILLs and reaps every child the worker still has and returns
// how many. It reaps by pid, never wait4(-1), which could steal another command's
// exit status. A survivor of waitDelay or an unreadable /proc is an error.
func killLeftovers() (int, error) {
	found := map[int]bool{}
	deadline := time.Now().Add(waitDelay)
	for {
		kids, err := children()
		if err != nil {
			return len(found), fmt.Errorf("listing leftover processes: %w", err)
		}
		if len(kids) == 0 {
			return len(found), nil
		}
		if time.Now().After(deadline) {
			return len(found), fmt.Errorf("%d leftover process(es) survived SIGKILL", len(kids))
		}
		for _, pid := range kids {
			found[pid] = true
			syscall.Kill(pid, syscall.SIGKILL)
			syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// children lists the pids whose parent is the worker. Any error but a process
// exiting mid-scan fails the scan, so an unreadable /proc never means no children.
func children() ([]int, error) {
	self := strconv.Itoa(os.Getpid())
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return nil, err
		}
		// comm may hold spaces or ')', so parse after the last ')'.
		f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
		if len(f) > 1 && f[1] == self {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// exitCode extracts a process exit status from a Run/Wait error. Go's ExitCode()
// returns -1 for a signal kill, so map signaled exits to 128+signo (SIGKILL ->
// 137) for the verdict classifier. ok is false when the process never reached an
// exit (spawn failure, or a context error that is not an ExitError).
func exitCode(err error) (code int, ok bool) {
	if err == nil {
		return 0, true
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), true
		}
		return ee.ExitCode(), true
	}
	return -1, false
}
