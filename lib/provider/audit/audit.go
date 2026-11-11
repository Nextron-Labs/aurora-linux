package audit

import (
	"errors"
	"io"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

const (
	maxAuditLineBytes = 8 * 1024 // audit lines are typically <4KB
	tailPollInterval  = 250 * time.Millisecond
	// recordIdleTimeout is how long a record must go without new lines before
	// it is treated as complete while tailing. It adds this much latency to
	// each event, in exchange for keeping a record's lines together.
	recordIdleTimeout = time.Second
)

// AuditProvider implements EventProvider by reading events from auditd log files.
// Each grouped audit record (lines sharing the same timestamp:serial) is flattened
// into one event per record type, with raw audit fields preserved for direct
// compatibility with SigmaHQ linux/auditd rules.
type AuditProvider struct {
	files        []string
	follow       atomic.Bool // when true, tail the last file for new lines
	sources      map[string]bool
	sourcesMu    sync.RWMutex
	closed       atomic.Bool
	lost         atomic.Uint64
	pollInterval time.Duration
	idleTimeout  time.Duration
}

// New creates a new AuditProvider for the given audit log files.
// By default follow mode is enabled, tailing the last file for real-time detection.
func New(files ...string) *AuditProvider {
	p := &AuditProvider{
		files:        files,
		sources:      make(map[string]bool),
		pollInterval: tailPollInterval,
		idleTimeout:  recordIdleTimeout,
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

// LostEvents returns the number of audit lines dropped because they could not be
// parsed.
func (a *AuditProvider) LostEvents() uint64 { return a.lost.Load() }

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
// The last file is tailed for new lines when follow mode is enabled, in which
// case this method blocks until Close() is called (like the eBPF listener).
func (a *AuditProvider) SendEvents(callback func(event provider.Event)) {
	for i, path := range a.files {
		if a.closed.Load() {
			return
		}
		if a.follow.Load() && i == len(a.files)-1 {
			a.followFile(path, callback)
		} else {
			a.readFile(path, callback)
		}
	}
}

// readFile reads path once from start to end.
func (a *AuditProvider) readFile(path string, callback func(event provider.Event)) {
	logger := log.WithFields(log.Fields{"provider": ProviderName, "path": path})

	current, err := openAuditLog(path)
	if err != nil {
		logger.WithError(err).Warn("Failed to open audit log file")
		return
	}
	defer current.close()

	grouper := newRecordGrouper()
	if err := a.drain(current, grouper, callback); err != nil && !errors.Is(err, io.EOF) {
		logger.WithField("line", current.lineNo).WithError(err).Warn("Error reading audit log")
	}
	a.emitRecords(grouper.Flush(), callback)
}

// followFile tails path until Close is called. It keeps following the path, not
// just the open file, so it survives log rotation and truncation and picks up a
// file that does not exist yet.
func (a *AuditProvider) followFile(path string, callback func(event provider.Event)) {
	logger := log.WithFields(log.Fields{"provider": ProviderName, "path": path})

	grouper := newRecordGrouper()
	defer func() { a.emitRecords(grouper.Flush(), callback) }()

	var current *auditLog
	defer func() {
		if current != nil {
			current.close()
		}
	}()

	// Only a file already present at startup is skipped to its end, because it
	// holds history. A file that appears later holds only new events.
	skipExisting := true
	warnedOpen, warnedRead := false, false
	lastExpiry := time.Now()

	for !a.closed.Load() {
		if now := time.Now(); now.Sub(lastExpiry) >= a.pollInterval {
			a.emitRecords(grouper.Expire(now.Add(-a.idleTimeout)), callback)
			lastExpiry = now
		}

		if current == nil {
			opened, err := openAuditLog(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					skipExisting = false
				}
				if !warnedOpen {
					logger.WithError(err).Warn("Failed to open audit log file; retrying until it is available")
					warnedOpen = true
				}
				time.Sleep(a.pollInterval)
				continue
			}
			warnedOpen = false
			if skipExisting {
				if err := opened.seekToEnd(); err != nil {
					logger.WithError(err).Warn("Failed to seek to end of audit log; reading from start")
				}
				skipExisting = false
			}
			current = opened
			logger.Info("Audit provider tailing file for real-time events")
		}

		line, err := current.lines.next()
		if err == nil {
			warnedRead = false
			a.processLine(current, line, grouper, callback)
			continue
		}
		if !errors.Is(err, io.EOF) && !warnedRead {
			logger.WithField("line", current.lineNo).WithError(err).Warn("Error reading audit log; retrying")
			warnedRead = true
		}

		switch current.status() {
		case logRotated:
			logger.Info("Audit log rotated; switching to the new file")
			// Pick up anything written to the old file since the last read.
			_ = a.drain(current, grouper, callback)
			current.close()
			current = nil
		case logTruncated:
			logger.Info("Audit log truncated; reading from the start")
			if err := current.rewind(); err != nil {
				logger.WithError(err).Warn("Failed to rewind audit log; reopening")
				current.close()
				current = nil
			}
		default:
			time.Sleep(a.pollInterval)
		}
	}
}

// drain processes the rest of the log, including a final line with no newline.
// It returns the error that ended reading (io.EOF at a clean end of file), or
// nil if Close was called first.
func (a *AuditProvider) drain(current *auditLog, grouper *recordGrouper, callback func(event provider.Event)) error {
	for !a.closed.Load() {
		line, err := current.lines.next()
		if err != nil {
			if rest := current.lines.remainder(); rest != "" {
				a.processLine(current, rest, grouper, callback)
			}
			return err
		}
		a.processLine(current, line, grouper, callback)
	}
	return nil
}

func (a *AuditProvider) processLine(current *auditLog, line string, grouper *recordGrouper, callback func(event provider.Event)) {
	current.lineNo++

	parsed, err := parseLine(line)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": ProviderName,
			"path":     current.path,
			"line":     current.lineNo,
		}).WithError(err).Debug("Skipping unparseable audit line")
		a.lost.Add(1)
		return
	}
	if parsed == nil {
		return
	}

	if completed := grouper.AddLine(parsed, time.Now()); completed != nil {
		a.emitRecord(completed, callback)
	}
}

func (a *AuditProvider) emitRecords(records []*auditRecord, callback func(event provider.Event)) {
	for _, record := range records {
		a.emitRecord(record, callback)
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
