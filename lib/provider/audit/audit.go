package audit

import (
	"bufio"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

const (
	maxAuditLineBytes = 8 * 1024 // audit lines are typically <4KB
	tailPollInterval  = 250 * time.Millisecond
)

// AuditProvider implements EventProvider by reading events from auditd log files.
// Each grouped audit record (lines sharing the same timestamp:serial) is flattened
// into one event per record type, with raw audit fields preserved for direct
// compatibility with SigmaHQ linux/auditd rules.
type AuditProvider struct {
	files     []string
	follow    atomic.Bool // when true, tail the last file for new lines
	sources   map[string]bool
	sourcesMu sync.RWMutex
	closed    atomic.Bool
	lost      atomic.Uint64
}

// New creates a new AuditProvider for the given audit log files.
// By default follow mode is enabled, tailing the last file for real-time detection.
func New(files ...string) *AuditProvider {
	p := &AuditProvider{
		files:   files,
		sources: make(map[string]bool),
	}
	p.follow.Store(true)
	return p
}

// SetFollow enables or disables follow (tail -f) mode on the last file.
func (a *AuditProvider) SetFollow(follow bool) {
	a.follow.Store(follow)
}

func (a *AuditProvider) Name() string        { return ProviderName }
func (a *AuditProvider) Description() string { return "Audit log provider for Linux auditd events" }
func (a *AuditProvider) LostEvents() uint64  { return a.lost.Load() }

func (a *AuditProvider) Close() error {
	a.closed.Store(true)
	return nil
}

func (a *AuditProvider) Initialize() error {
	a.closed.Store(false)
	return nil
}

func (a *AuditProvider) AddSource(source string) error {
	a.sourcesMu.Lock()
	a.sources[source] = true
	a.sourcesMu.Unlock()
	return nil
}

// SendEvents reads each audit log file and emits events via the callback.
// The last file is tailed for new lines when follow mode is enabled.
// This method blocks until Close() is called (like the eBPF listener).
func (a *AuditProvider) SendEvents(callback func(event provider.Event)) {
	for i, path := range a.files {
		if a.closed.Load() {
			return
		}
		isLast := i == len(a.files)-1
		follow := a.follow.Load() && isLast
		a.processFile(path, follow, callback)
	}
}

func (a *AuditProvider) processFile(path string, follow bool, callback func(event provider.Event)) {
	f, err := os.Open(path)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": ProviderName,
			"path":     path,
		}).WithError(err).Warn("Failed to open audit log file")
		return
	}
	defer f.Close()

	if follow {
		// Seek to end — only process new lines in follow mode.
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			log.WithFields(log.Fields{
				"provider": ProviderName,
				"path":     path,
			}).WithError(err).Warn("Failed to seek to end of audit log; reading from start")
		} else {
			log.WithField("path", path).Info("Audit provider tailing file for real-time events")
		}
	}

	lineNo := 0
	grouper := newRecordGrouper()
	reader := bufio.NewReader(f)

	for !a.closed.Load() {
		line, err := readLine(reader)
		if err != nil && err != io.EOF {
			log.WithFields(log.Fields{
				"provider": ProviderName,
				"path":     path,
				"line":     lineNo,
			}).WithError(err).Warn("Error reading audit log")
			return
		}

		if line == "" {
			if !follow || err == io.EOF {
				if !follow {
					// Non-follow: flush and return at EOF.
					break
				}
				// Follow mode: flush pending group on EOF (auditd writes
				// complete record groups atomically, so if we hit EOF the
				// current group is complete).
				if final := grouper.Flush(); final != nil {
					a.emitRecord(final, callback)
				}
				// Poll for new data
				time.Sleep(tailPollInterval)
				continue
			}
		}

		lineNo++

		parsed, err := parseLine(line)
		if err != nil {
			log.WithFields(log.Fields{
				"provider": ProviderName,
				"path":     path,
				"line":     lineNo,
			}).WithError(err).Debug("Skipping unparseable audit line")
			a.lost.Add(1)
			continue
		}
		if parsed == nil {
			continue
		}

		if completed := grouper.AddLine(parsed); completed != nil {
			a.emitRecord(completed, callback)
		}
	}

	// Flush the last pending record
	if final := grouper.Flush(); final != nil {
		a.emitRecord(final, callback)
	}
}

// readLine reads a complete line from the reader, handling partial reads.
// Returns the line without the trailing newline, or io.EOF at end of file.
// Lines exceeding maxAuditLineBytes are truncated to prevent unbounded allocation.
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
		if len(line)+len(part) > maxAuditLineBytes {
			// Discard the rest of the oversized line.
			line = append(line, part[:maxAuditLineBytes-len(line)]...)
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

func (a *AuditProvider) emitRecord(record *auditRecord, callback func(event provider.Event)) {
	events := mapRecordToEvents(record)
	for _, evt := range events {
		if !a.sourceEnabled(evt.source) {
			continue
		}
		callback(evt)
	}
}

func (a *AuditProvider) sourceEnabled(source string) bool {
	a.sourcesMu.RLock()
	defer a.sourcesMu.RUnlock()
	if len(a.sources) == 0 {
		return true
	}
	return a.sources[source]
}
