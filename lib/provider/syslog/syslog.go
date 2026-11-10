package syslog

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

const (
	maxLineBytes = 16 * 1024
	pollInterval = 250 * time.Millisecond
)

// Provider tails syslog files and/or the systemd journal.
type Provider struct {
	files   []string
	journal bool
	// readFromStart processes existing file content instead of only new lines
	// (used for batch analysis and tests).
	readFromStart bool

	selfPID uint32
	closed  atomic.Bool
	lost    atomic.Uint64
	wg      sync.WaitGroup

	mu  sync.Mutex
	cmd *exec.Cmd
}

// New creates a provider for the given files; journal also follows journald.
func New(files []string, journal bool) *Provider {
	return &Provider{files: files, journal: journal, selfPID: uint32(os.Getpid())}
}

// SetReadFromStart makes file tailing start at the beginning of each file.
func (p *Provider) SetReadFromStart(v bool) { p.readFromStart = v }

func (p *Provider) Name() string           { return ProviderName }
func (p *Provider) Description() string    { return "Syslog / journald input provider" }
func (p *Provider) LostEvents() uint64     { return p.lost.Load() }
func (p *Provider) AddSource(string) error { return nil }
func (p *Provider) Initialize() error      { p.closed.Store(false); return nil }

// Close stops all readers.
func (p *Provider) Close() error {
	p.closed.Store(true)
	p.mu.Lock()
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	p.mu.Unlock()
	return nil
}

// SendEvents blocks until Close is called.
func (p *Provider) SendEvents(callback func(provider.Event)) {
	for _, f := range p.files {
		p.wg.Add(1)
		go func(path string) { defer p.wg.Done(); p.tailFile(path, callback) }(f)
	}
	if p.journal {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.followJournal(callback) }()
	}
	p.wg.Wait()
}

// isSelf drops Aurora's own log lines so its alerts are never re-ingested
// (re-ingesting an alert would re-trigger the keyword rule that produced it,
// in a loop). Only lines whose whole shape is an Aurora alert are dropped:
// a marker anywhere in a line is attacker-controlled (e.g. an SSH user name
// "sigma_rule=x" in sshd's "Invalid user ..." line) and must not hide it.
func (p *Provider) isSelf(pid, message string) bool {
	if pid != "" && p.selfPID != 0 && pid == strconv.FormatUint(uint64(p.selfPID), 10) {
		return true
	}
	return looksLikeAuroraAlert(message)
}

// Aurora's alert messages and the field each one always carries.
var selfAlertShapes = []struct{ prefix, key string }{
	{"Sigma match", "sigma_rule"},
	{"IOC match", "ioc_type"},
	{"Aurora tamper alert: ", "alert_type"},
}

// textLogPrefix matches the timestamp and level of Aurora's text format.
var textLogPrefix = regexp.MustCompile(`^\S+ (?:TRACE|DEBUG|INFO|WARNING|ERROR|FATAL|PANIC) `)

// looksLikeAuroraAlert reports whether a syslog message is one of Aurora's
// alerts in JSON, text or syslog format.
func looksLikeAuroraAlert(m string) bool {
	m = strings.TrimSpace(m)
	if strings.HasPrefix(m, "{") {
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(m), &obj) != nil {
			return false
		}
		var msg string
		if json.Unmarshal(obj["message"], &msg) != nil {
			return false
		}
		for _, sh := range selfAlertShapes {
			if _, ok := obj[sh.key]; ok && (msg == strings.TrimSpace(sh.prefix) || strings.HasPrefix(msg, sh.prefix)) {
				return true
			}
		}
		return false
	}
	if loc := textLogPrefix.FindStringIndex(m); loc != nil {
		m = m[loc[1]:]
	}
	for _, sh := range selfAlertShapes {
		if strings.HasPrefix(m, sh.prefix) && strings.Contains(m, " "+sh.key+"=") {
			return true
		}
	}
	return false
}

func (p *Provider) emit(pr Parsed, raw, logSource string, ts time.Time, callback func(provider.Event)) {
	if p.isSelf(pr.PID, pr.Message) {
		return
	}
	f := make(enrichment.DataFieldsMap, 9)
	f.AddField("message", pr.Message)
	f.AddField("raw", raw)
	f.AddField("program", pr.Program)
	f.AddField("pid", pr.PID)
	f.AddField("hostname", pr.Hostname)
	f.AddField("facility", pr.Facility)
	f.AddField("severity", pr.Severity)
	f.AddField("log_source", logSource)

	var pid uint32
	if n, err := strconv.ParseUint(pr.PID, 10, 32); err == nil {
		pid = uint32(n)
	}
	callback(&syslogEvent{pid: pid, ts: ts, fields: f, services: ServicesFor(pr.Program, pr.Facility)})
}

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------

func (p *Provider) tailFile(path string, callback func(provider.Event)) {
	var f *os.File
	var ino uint64
	var lr lineReader
	first := true

	open := func(fromStart bool) bool {
		// Regular files only: a FIFO would block open() forever and a
		// device such as /dev/zero would spin the reader.
		if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
			return false
		}
		nf, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return false
		}
		if st, err := nf.Stat(); err != nil || !st.Mode().IsRegular() {
			nf.Close()
			return false
		}
		if !fromStart {
			if _, err := nf.Seek(0, io.SeekEnd); err != nil {
				nf.Close()
				return false
			}
		}
		if f != nil {
			f.Close()
		}
		f, lr, ino = nf, lineReader{r: bufio.NewReaderSize(nf, 64*1024)}, inodeOf(nf)
		return true
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	var warned bool
	for !p.closed.Load() {
		if f == nil {
			if !open(p.readFromStart && first || !first) {
				if !warned {
					log.WithField("path", path).Warn("Syslog file not readable yet; will keep retrying")
					warned = true
				}
				time.Sleep(time.Second)
				continue
			}
			if first {
				log.WithField("path", path).Info("Syslog provider tailing file")
			}
			first = false
		}

		if line, ok := lr.next(); ok {
			p.handleLine(line, "file:"+path, callback)
			continue
		}
		// EOF: wait, then check for rotation/truncation.
		time.Sleep(pollInterval)
		if rotated(path, f, ino) {
			// The writer may still append to the rotated file until it
			// reopens its log (logrotate "create" + HUP): drain it first.
			p.drain(&lr, path, callback)
			f.Close()
			f = nil // reopen from the start of the new file
		}
	}
}

// drain reads what is left in a rotated file, with a short grace period for
// writers that have not reopened their log yet.
func (p *Provider) drain(lr *lineReader, path string, callback func(provider.Event)) {
	deadline := time.Now().Add(2 * time.Second)
	idle := 0
	for !p.closed.Load() && time.Now().Before(deadline) && idle < 4 {
		if line, ok := lr.next(); ok {
			p.handleLine(line, "file:"+path, callback)
			idle = 0
			continue
		}
		idle++
		time.Sleep(pollInterval)
	}
}

func (p *Provider) handleLine(line, logSource string, callback func(provider.Event)) {
	if strings.TrimSpace(line) == "" {
		return
	}
	p.emit(ParseLine(line), line, logSource, time.Now(), callback)
}

// lineReader returns complete lines only: a final fragment without a newline
// stays pending until the rest arrives (a writer may flush mid-line), and
// lines longer than maxLineBytes are truncated.
type lineReader struct {
	r       *bufio.Reader
	pending []byte
}

// next returns the next complete line, or ok=false at EOF/error.
func (lr *lineReader) next() (line string, ok bool) {
	for {
		chunk, err := lr.r.ReadSlice('\n')
		if room := maxLineBytes - len(lr.pending); room > 0 {
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			lr.pending = append(lr.pending, chunk...)
		}
		switch err {
		case nil:
			line = strings.TrimRight(string(lr.pending), "\r\n")
			lr.pending = lr.pending[:0]
			return line, true
		case bufio.ErrBufferFull:
			continue // very long line: keep consuming (bounded above)
		default:
			return "", false // EOF: wait for the rest of the line
		}
	}
}

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

type journalEntry struct {
	Message   json.RawMessage `json:"MESSAGE"`
	Ident     string          `json:"SYSLOG_IDENTIFIER"`
	Comm      string          `json:"_COMM"`
	PID       string          `json:"_PID"`
	Hostname  string          `json:"_HOSTNAME"`
	Priority  string          `json:"PRIORITY"`
	Facility  string          `json:"SYSLOG_FACILITY"`
	Timestamp string          `json:"__REALTIME_TIMESTAMP"`
	Cursor    string          `json:"__CURSOR"`
}

// journalMaxLine bounds one journal JSON line; longer entries are dropped
// (and counted) instead of stalling the reader.
const journalMaxLine = 1 << 20

// decodeJournalMessage accepts both encodings journalctl uses for MESSAGE:
// a JSON string, or an array of byte values for non-UTF-8/binary content.
func decodeJournalMessage(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	var b []byte
	var nums []int
	if err := json.Unmarshal(raw, &nums); err == nil {
		b = make([]byte, 0, len(nums))
		for _, n := range nums {
			if n < 0 || n > 255 {
				return "", false
			}
			b = append(b, byte(n))
		}
		return strings.ToValidUTF8(string(b), "\uFFFD"), true
	}
	return "", false
}

// parseJournalLine converts one `journalctl -o json` line. cursor is the
// entry's position, used to resume after journalctl restarts.
func parseJournalLine(line []byte) (p Parsed, raw string, ts time.Time, cursor string, ok bool) {
	var e journalEntry
	if err := json.Unmarshal(line, &e); err != nil {
		return Parsed{}, "", time.Time{}, "", false
	}
	msg, ok := decodeJournalMessage(e.Message)
	if !ok {
		return Parsed{}, "", time.Time{}, e.Cursor, false
	}
	p = Parsed{Message: msg, PID: e.PID, Hostname: e.Hostname, Program: e.Ident}
	if p.Program == "" {
		p.Program = e.Comm
	}
	if n, err := strconv.Atoi(e.Priority); err == nil && n >= 0 && n < len(severityNames) {
		p.Severity = severityNames[n]
	}
	if n, err := strconv.Atoi(e.Facility); err == nil && n >= 0 && n < len(facilityNames) {
		p.Facility = facilityNames[n]
	}
	ts = time.Now()
	if us, err := strconv.ParseInt(e.Timestamp, 10, 64); err == nil {
		ts = time.UnixMicro(us)
	}
	return p, strings.TrimSpace(p.Program + "[" + p.PID + "]: " + msg), ts, e.Cursor, true
}

// journalctlPath resolves journalctl once from trusted locations (never via
// the caller's PATH).
func journalctlPath() string {
	for _, c := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			return c
		}
	}
	return ""
}

func (p *Provider) followJournal(callback func(provider.Event)) {
	bin := journalctlPath()
	if bin == "" {
		log.Warn("Syslog provider: journalctl not found; journal input disabled")
		return
	}
	cursor := ""
	for !p.closed.Load() {
		// --all: without it journalctl prints fields longer than 4096 bytes
		// as null, which would hide long (attacker-padded) messages.
		args := []string{"-f", "-o", "json", "--all", "--no-pager"}
		if cursor != "" {
			args = append(args, "--after-cursor", cursor) // no gap after a restart
		} else {
			args = append(args, "-n", "0")
		}
		cmd := exec.Command(bin, args...)
		cmd.SysProcAttr = childProcAttr()
		out, err := cmd.StdoutPipe()
		if err != nil {
			return
		}
		if err := cmd.Start(); err != nil {
			log.WithError(err).Warn("Syslog provider: cannot run journalctl; journal input disabled")
			return
		}
		p.mu.Lock()
		p.cmd = cmd
		closed := p.closed.Load()
		p.mu.Unlock()
		if closed { // Close() ran between the loop check and registration
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return
		}
		log.Info("Syslog provider following the systemd journal")

		r := bufio.NewReaderSize(out, 64*1024)
		var buf []byte
		for {
			chunk, err := r.ReadSlice('\n')
			if len(buf)+len(chunk) <= journalMaxLine {
				buf = append(buf, chunk...)
			} else {
				buf = buf[:0]
				p.lost.Add(1)
				if err == bufio.ErrBufferFull {
					// discard the rest of the oversized line
					for err == bufio.ErrBufferFull {
						_, err = r.ReadSlice('\n')
					}
					continue
				}
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				break
			}
			if pr, raw, ts, cur, ok := parseJournalLine(buf); ok {
				p.emit(pr, raw, "journal", ts, callback)
				cursor = cur
			} else {
				if cur != "" {
					cursor = cur
				}
				p.lost.Add(1)
			}
			buf = buf[:0]
		}
		// Never Wait() on a journalctl that may be blocked writing to us.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if p.closed.Load() {
			return
		}
		time.Sleep(2 * time.Second) // journalctl exited unexpectedly: restart
	}
}
