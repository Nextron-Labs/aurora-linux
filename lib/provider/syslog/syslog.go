// Package syslog implements an EventProvider that reads syslog messages on
// a wide range of Linux distributions and emits one provider.Event per
// parsed line.
//
// Two source types are supported, which together cover essentially every
// mainstream distribution shipping today:
//
//   - Plain-text files (rsyslog / syslog-ng): /var/log/syslog (Debian,
//     Ubuntu, Mint, Pop!_OS, Kali, Raspberry Pi OS),  /var/log/messages
//     (RHEL/CentOS/Rocky/Alma/Fedora, Amazon Linux, Oracle Linux, SUSE,
//     openSUSE, Arch with rsyslog, Gentoo), plus auth/secure/kern.log.
//   - journald (via `journalctl --follow`): for systemd-only distributions
//     that have removed rsyslog (modern Fedora, RHEL 8+ minimal installs,
//     Arch without rsyslog, etc.).
//
// DefaultCandidatePaths returns the file probe list; DetectSyslogFiles
// returns the readable subset for the running host. NewAuto chains these
// together with a journald fallback.
package syslog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

const (
	maxSyslogLineBytes = 64 * 1024
	tailPollInterval   = 250 * time.Millisecond

	// SourceJournald is a synthetic source emitted for events read from
	// journalctl rather than from a syslog file.
	SourceJournald = "LinuxSyslog:Journald"

	// defaultJournalctlBinary is used when Config.JournalctlPath is empty.
	defaultJournalctlBinary = "journalctl"
)

// Config controls which sources the syslog provider reads from.
type Config struct {
	// Files is the list of syslog file paths to tail.
	Files []string
	// UseJournald enables tailing the systemd journal via journalctl.
	UseJournald bool
	// JournalctlPath optionally overrides the journalctl binary location
	// (defaults to whatever PATH resolves "journalctl" to).
	JournalctlPath string
}

// SyslogProvider reads syslog messages from one or more sources and emits
// one provider.Event per parsed line.
type SyslogProvider struct {
	cfg     Config
	follow  atomic.Bool
	sources map[string]bool
	mu      sync.RWMutex
	closed  atomic.Bool
	lost    atomic.Uint64

	cancelJournald context.CancelFunc
	journaldCmd    *exec.Cmd
}

// New constructs a SyslogProvider from the given configuration. Follow
// (tail -f) mode is enabled by default; switch it off via SetFollow for
// replay-style tests where the provider should return at EOF.
func New(cfg Config) *SyslogProvider {
	cfg.Files = append([]string(nil), cfg.Files...)
	p := &SyslogProvider{
		cfg:     cfg,
		sources: make(map[string]bool),
	}
	p.follow.Store(true)
	return p
}

// NewFromFiles is a convenience constructor for the file-only case.
func NewFromFiles(files ...string) *SyslogProvider {
	return New(Config{Files: files})
}

// SetFollow toggles tail-on-EOF behaviour. With follow=false, SendEvents
// returns once each file has been read to EOF (used by tests).
func (s *SyslogProvider) SetFollow(follow bool) {
	s.follow.Store(follow)
}

func (s *SyslogProvider) Name() string {
	return ProviderName
}

func (s *SyslogProvider) Description() string {
	return "Syslog provider tailing /var/log/{syslog,messages,...} and/or journald"
}

func (s *SyslogProvider) LostEvents() uint64 { return s.lost.Load() }

// Files returns the active set of syslog files (after Initialize has
// dropped unreadable ones). Useful for logging in callers.
func (s *SyslogProvider) Files() []string {
	return append([]string(nil), s.cfg.Files...)
}

// JournaldEnabled reports whether journald is part of the active source set.
func (s *SyslogProvider) JournaldEnabled() bool { return s.cfg.UseJournald }

func (s *SyslogProvider) Close() error {
	s.closed.Store(true)
	if s.cancelJournald != nil {
		s.cancelJournald()
	}
	return nil
}

// Initialize verifies that at least one configured source is usable and
// drops unreadable files from the active set. If every configured source
// fails this returns an error so the agent fails loudly at startup —
// this is the requested "raise an alert if it is not possible to read
// syslog" behaviour.
func (s *SyslogProvider) Initialize() error {
	s.closed.Store(false)

	if len(s.cfg.Files) == 0 && !s.cfg.UseJournald {
		return errors.New("syslog provider: no sources configured (no files and journald disabled)")
	}

	var (
		readable []string
		firstErr error
	)
	for _, path := range s.cfg.Files {
		f, err := os.Open(path)
		if err != nil {
			log.WithFields(log.Fields{
				"provider": ProviderName,
				"path":     path,
			}).WithError(err).Warn("Syslog file is not readable; skipping")
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		_ = f.Close()
		readable = append(readable, path)
	}
	s.cfg.Files = readable

	if s.cfg.UseJournald {
		if err := checkJournalctl(s.cfg.JournalctlPath); err != nil {
			log.WithError(err).Warn("Syslog provider: journald source unavailable")
			s.cfg.UseJournald = false
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	if len(s.cfg.Files) == 0 && !s.cfg.UseJournald {
		return fmt.Errorf(
			"syslog provider: unable to read any syslog source (files and journald all failed); first error: %v",
			firstErr,
		)
	}

	return nil
}

func (s *SyslogProvider) AddSource(source string) error {
	s.mu.Lock()
	s.sources[source] = true
	s.mu.Unlock()
	return nil
}

// SendEvents reads from each configured source and emits one event per
// parsed line via callback. In follow mode (the default) one goroutine per
// source tails for new appends; this method blocks until Close() is
// called. In non-follow mode files are read serially to EOF and the method
// returns; journald is skipped in non-follow mode.
func (s *SyslogProvider) SendEvents(callback func(event provider.Event)) {
	follow := s.follow.Load()

	if !follow {
		for _, path := range s.cfg.Files {
			if s.closed.Load() {
				return
			}
			s.processFile(path, false, callback)
		}
		return
	}

	var wg sync.WaitGroup
	for _, path := range s.cfg.Files {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			s.processFile(p, true, callback)
		}(path)
	}
	if s.cfg.UseJournald {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.processJournald(callback)
		}()
	}
	wg.Wait()
}

func (s *SyslogProvider) processFile(path string, follow bool, callback func(event provider.Event)) {
	f, err := os.Open(path)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": ProviderName,
			"path":     path,
		}).WithError(err).Warn("Failed to open syslog file")
		return
	}
	defer func() {
		_ = f.Close()
	}()

	if follow {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			log.WithFields(log.Fields{
				"provider": ProviderName,
				"path":     path,
			}).WithError(err).Warn("Failed to seek to end of syslog file; reading from start")
		} else {
			log.WithField("path", path).Info("Syslog provider tailing file for real-time events")
		}
	}

	reader := bufio.NewReaderSize(f, maxSyslogLineBytes)
	lineNo := 0

	for !s.closed.Load() {
		line, err := readLine(reader)
		if err != nil && err != io.EOF {
			log.WithFields(log.Fields{
				"provider": ProviderName,
				"path":     path,
				"line":     lineNo,
			}).WithError(err).Warn("Error reading syslog file")
			s.lost.Add(1)
			return
		}

		if line == "" {
			if !follow || err == io.EOF {
				if !follow {
					return
				}
				time.Sleep(tailPollInterval)
				continue
			}
		}

		lineNo++
		s.dispatchLine(line, SourceSyslog, callback)
	}
}

func (s *SyslogProvider) processJournald(callback func(event provider.Event)) {
	binary := s.cfg.JournalctlPath
	if binary == "" {
		binary = defaultJournalctlBinary
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancelJournald = cancel
	defer cancel()

	cmd := exec.CommandContext(ctx, binary,
		"--follow",
		"--output=short-iso",
		"--no-pager",
		"--since=now",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.WithError(err).Warn("Syslog provider: failed to open journalctl stdout pipe")
		s.lost.Add(1)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.WithError(err).Warn("Syslog provider: failed to open journalctl stderr pipe")
		s.lost.Add(1)
		return
	}
	if err := cmd.Start(); err != nil {
		log.WithError(err).Warn("Syslog provider: failed to start journalctl")
		s.lost.Add(1)
		return
	}
	s.journaldCmd = cmd
	log.Info("Syslog provider tailing journald via journalctl --follow")

	go drainStderr(stderr)

	reader := bufio.NewReaderSize(stdout, maxSyslogLineBytes)
	for !s.closed.Load() {
		line, err := readLine(reader)
		if err != nil && err != io.EOF {
			log.WithError(err).Warn("Error reading from journalctl")
			s.lost.Add(1)
			break
		}
		if line == "" {
			if err == io.EOF {
				break
			}
			continue
		}
		s.dispatchLine(line, SourceJournald, callback)
	}

	_ = cmd.Wait()
}

func drainStderr(r io.Reader) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			log.WithField("provider", ProviderName).Debug("journalctl stderr: ", line)
		}
		if err != nil {
			return
		}
	}
}

func (s *SyslogProvider) dispatchLine(line, source string, callback func(event provider.Event)) {
	parsed := parseLine(line)
	if parsed == nil {
		return
	}
	evt := mapLineToEvent(parsed, source)
	if !s.sourceEnabled(source) {
		return
	}
	callback(evt)
}

// readLine reads one complete logical line, capping the buffered length
// at maxSyslogLineBytes to avoid unbounded allocation on pathological
// input.
func readLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		part, isPrefix, err := r.ReadLine()
		if err != nil {
			if len(line) > 0 {
				return string(line), nil
			}
			return "", err
		}
		if len(line)+len(part) > maxSyslogLineBytes {
			line = append(line, part[:maxSyslogLineBytes-len(line)]...)
			for isPrefix {
				_, isPrefix, err = r.ReadLine()
				if err != nil {
					break
				}
			}
			return string(line), nil
		}
		line = append(line, part...)
		if !isPrefix {
			return string(line), nil
		}
	}
}

func mapLineToEvent(line *syslogLine, source string) *syslogEvent {
	fields := make(enrichment.DataFieldsMap, 8)
	fields.AddField("type", "syslog")
	if line.Raw != "" {
		fields.AddField("raw", line.Raw)
	}
	if line.Message != "" {
		fields.AddField("message", line.Message)
	}
	if line.Host != "" {
		fields.AddField("host", line.Host)
	}
	if line.Program != "" {
		fields.AddField("program", line.Program)
		fields.AddField("Image", line.Program)
	}
	if line.PID != 0 {
		pidStr := fmt.Sprintf("%d", line.PID)
		fields.AddField("pid", pidStr)
		fields.AddField("ProcessId", pidStr)
	}

	return &syslogEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDSyslog,
		},
		pid:    line.PID,
		source: source,
		ts:     line.Timestamp,
		fields: fields,
	}
}

func (s *SyslogProvider) sourceEnabled(source string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.sources) == 0 {
		return true
	}
	return s.sources[source]
}

func checkJournalctl(binary string) error {
	if binary == "" {
		binary = defaultJournalctlBinary
	}
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("journalctl not found in PATH: %w", err)
	}
	return nil
}
