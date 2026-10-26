package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	maxPixels   = 9437184
	maxLongSide = 4096
	maxStreams  = 32
	maxAlloc    = 268435456 // 256 MiB per single allocation
)

const probeTimeout = 20 * time.Second

// codecs maps each accepted ffprobe codec name to the decoder FFmpeg opens. The
// whitelist matches decoder names, so AV1 is libdav1d and MP3 is mp3float.
var codecs = map[string]string{
	"h264": "h264", "hevc": "hevc", "av1": "libdav1d", "vp9": "vp9", "mpeg4": "mpeg4",
	"aac": "aac", "ac3": "ac3", "eac3": "eac3", "mp3": "mp3float",
	"opus": "opus", "flac": "flac", "vorbis": "vorbis",
	"pcm_s16le": "pcm_s16le", "pcm_s24le": "pcm_s24le", "pcm_f32le": "pcm_f32le",
}

// inputGuards are the limits both stages place before -i. -max_streams is one
// past the cap, since Matroska and MPEG-TS stop at the cap and still exit 0.
func inputGuards(protocols string) []string {
	return []string{
		"-protocol_whitelist", protocols,
		"-format_whitelist", "mov,matroska,avi,mpegts",
		"-codec_whitelist", strings.Join(slices.Sorted(maps.Values(codecs)), ","),
		"-max_streams", fmt.Sprint(maxStreams + 1),
		"-max_pixels", fmt.Sprint(maxPixels),
		"-max_alloc", fmt.Sprint(maxAlloc),
	}
}

type ffStream struct {
	CodecType   string `json:"codec_type"`
	CodecName   string `json:"codec_name"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Disposition struct {
		AttachedPic int `json:"attached_pic"`
	} `json:"disposition"`
}

type ffProbeOut struct {
	Streams []ffStream `json:"streams"`
	Format  struct {
		FormatName string `json:"format_name"`
	} `json:"format"`
}

// probeGate returns the rejection for a file, or nil.
//
// Local files use the file protocol and no nonet (ffprobe needs the network in
// production, where the whitelist is https,tls,tcp with -ca_file for S3). The
// resource ceilings are identical either way. See deploy/AWS-CONTROLS.md.
func probeGate(ctx context.Context, t tools, file string) error {
	if t.ffprobe == "" {
		return fmt.Errorf("ffprobe not found")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	args := []string{
		"-v", "error", "-of", "json",
		"-show_entries", "stream=codec_type,codec_name,width,height:stream_disposition=attached_pic:format=format_name",
	}
	args = append(args, inputGuards("file")...)
	args = append(args, "-i", file)
	out, err := t.cmd(ctx, t.ffprobe, args...).Output()
	// ffprobe never forks, so any leftover process is a hijack's.
	if n, kerr := killLeftovers(); kerr != nil {
		return fmt.Errorf("Probe.Rejected: %w (hostile input)", kerr)
	} else if n > 0 {
		return fmt.Errorf("Probe.Rejected: ffprobe left %d process(es) running (hostile input)", n)
	}
	if err != nil {
		// A deadline overrun may mean a slow call, not a bad file, so it is transient.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("Probe.Transient: ffprobe passed its %v deadline", probeTimeout)
		}
		return fmt.Errorf("Probe.Rejected: ffprobe %s", ffprobeFailure(err))
	}

	var p ffProbeOut
	if err := json.Unmarshal(out, &p); err != nil {
		return fmt.Errorf("Probe.Rejected: unparseable ffprobe output: %w", err)
	}
	if len(p.Streams) > maxStreams {
		return fmt.Errorf("Probe.Rejected: more than %d streams", maxStreams)
	}

	// Only V:0 and the first audio stream are decoded, so only those are checked.
	// ffprobe merely warns when a decoder isn't compiled in.
	var video, audio *ffStream
	for i := range p.Streams {
		s := &p.Streams[i]
		switch {
		case s.CodecType == "video" && s.Disposition.AttachedPic == 0 && video == nil:
			video = s
		case s.CodecType == "audio" && audio == nil:
			audio = s
		}
	}
	if video == nil {
		return fmt.Errorf("Probe.Rejected: no video stream")
	}
	if _, ok := codecs[video.CodecName]; !ok {
		return fmt.Errorf("Probe.Rejected: unsupported video codec %s", video.CodecName)
	}
	if audio != nil {
		if _, ok := codecs[audio.CodecName]; !ok {
			return fmt.Errorf("Probe.Rejected: unsupported audio codec %s", audio.CodecName)
		}
	}
	if video.Width <= 0 || video.Height <= 0 {
		return fmt.Errorf("Probe.Rejected: video stream has no valid dimensions (%dx%d)", video.Width, video.Height)
	}
	// Long-side check first, so the pixel multiply below cannot overflow.
	if long := max(video.Width, video.Height); long > maxLongSide {
		return fmt.Errorf("Probe.Rejected: video long side %d exceeds %d", long, maxLongSide)
	}
	if video.Width*video.Height > maxPixels {
		return fmt.Errorf("Probe.Rejected: %d pixels exceeds %d", video.Width*video.Height, maxPixels)
	}

	fmt.Printf("Probe.Accepted: container=%s video=%s %dx%d streams=%d\n",
		strings.SplitN(p.Format.FormatName, ",", 2)[0],
		video.CodecName, video.Width, video.Height, len(p.Streams))
	return nil
}

func ffprobeFailure(err error) string {
	ee, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		return err.Error()
	}
	code, _ := exitCode(err)
	msg := fmt.Sprintf("exit %d", code)
	if line, _, _ := strings.Cut(strings.TrimSpace(string(ee.Stderr)), "\n"); line != "" {
		msg += ": " + line
	}
	return msg
}
