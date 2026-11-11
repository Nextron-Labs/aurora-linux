package audit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

func mustParse(t *testing.T, line string) *auditLine {
	t.Helper()
	parsed, err := parseLine(line)
	if err != nil {
		t.Fatalf("parseLine(%q): %v", line, err)
	}
	return parsed
}

func TestParseLineNodePrefix(t *testing.T) {
	parsed := mustParse(t, `node=host1 type=SYSCALL msg=audit(1775057805.797:696): syscall=59 key="k"`)

	if parsed.RecordType != "SYSCALL" {
		t.Errorf("RecordType = %q, want SYSCALL", parsed.RecordType)
	}
	if parsed.AuditID != "1775057805.797:696" {
		t.Errorf("AuditID = %q, want 1775057805.797:696", parsed.AuditID)
	}
	if parsed.Fields["node"] != "host1" {
		t.Errorf("node = %q, want host1", parsed.Fields["node"])
	}
	if parsed.Fields["key"] != "k" {
		t.Errorf("key = %q, want k", parsed.Fields["key"])
	}
}

func TestHexDecodingOnlyAppliesToUnquotedValues(t *testing.T) {
	tests := []struct {
		name, line, field, want string
	}{
		{"quoted hex-like command", `type=EXECVE msg=audit(1.0:1): a0="dd"`, "a0", "dd"},
		{"quoted numeric argument", `type=EXECVE msg=audit(1.0:1): a1="4755"`, "a1", "4755"},
		{"unquoted hex argument", `type=EXECVE msg=audit(1.0:1): a1=2D6C61`, "a1", "-la"},
		{"unquoted split argument", `type=EXECVE msg=audit(1.0:1): a2[0]=4142`, "a2[0]", "AB"},
		{"quoted split argument", `type=EXECVE msg=audit(1.0:1): a2[0]="4142"`, "a2[0]", "4142"},
		{"argument length is decimal", `type=EXECVE msg=audit(1.0:1): a2_len=8192`, "a2_len", "8192"},
		{"quoted proctitle", `type=PROCTITLE msg=audit(1.0:1): proctitle="abcd"`, "proctitle", "abcd"},
		{"unquoted proctitle", `type=PROCTITLE msg=audit(1.0:1): proctitle=2D62617368`, "proctitle", "-bash"},
		{"syscall args stay raw", `type=SYSCALL msg=audit(1.0:1): a0=ffff`, "a0", "ffff"},
		{"unquoted exe", `type=SYSCALL msg=audit(1.0:1): exe=2F746D702F612062`, "exe", "/tmp/a b"},
		{"unquoted comm", `type=SYSCALL msg=audit(1.0:1): comm=612062`, "comm", "a b"},
		{"unquoted name", `type=PATH msg=audit(1.0:1): name=2F746D702F612062`, "name", "/tmp/a b"},
		{"unquoted cwd", `type=CWD msg=audit(1.0:1): cwd=2F746D702F612062`, "cwd", "/tmp/a b"},
		{"unquoted exe in another record type", `type=ANOM_ABEND msg=audit(1.0:1): exe=2F746D702F612062`, "exe", "/tmp/a b"},
		{"quoted hex-like comm", `type=SYSCALL msg=audit(1.0:1): comm="abcd"`, "comm", "abcd"},
		{"quoted hex-like name", `type=PATH msg=audit(1.0:1): name="abcd"`, "name", "abcd"},
		{"null name placeholder", `type=PATH msg=audit(1.0:1): name=(null)`, "name", "(null)"},
		{"unknown exe placeholder", `type=USER_AUTH msg=audit(1.0:1): exe=?`, "exe", "?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustParse(t, tt.line).Fields[tt.field]; got != tt.want {
				t.Errorf("%s = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

func TestDecodedSyscallFieldsAreMergedIntoChildEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, `type=SYSCALL msg=audit(1.0:1): key="k" exe=2F746D702F612062`+"\n"+
		`type=PATH msg=audit(1.0:1): item=0 name=2F746D702F612062`+"\n")

	got := readAll(t, path)
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if v := got[1].Value("exe").String; v != "/tmp/a b" {
		t.Errorf("PATH exe (from SYSCALL) = %q, want /tmp/a b", v)
	}
	if v := got[1].Value("name").String; v != "/tmp/a b" {
		t.Errorf("PATH name = %q, want /tmp/a b", v)
	}
}

func TestParseLineEnrichedFormat(t *testing.T) {
	tests := []struct {
		name, line string
		want       map[string]string
	}{
		{
			name: "separator after quoted value",
			line: "type=SYSCALL msg=audit(1.0:1): syscall=59 key=\"k\"\x1dARCH=x86_64 SYSCALL=execve AUID=\"root\" UID=\"root\"",
			want: map[string]string{"syscall": "59", "key": "k", "ARCH": "x86_64", "SYSCALL": "execve", "AUID": "root", "UID": "root"},
		},
		{
			name: "separator after unquoted value",
			line: "type=SYSCALL msg=audit(1.0:1): syscall=59 key=(null)\x1dARCH=x86_64 SYSCALL=execve",
			want: map[string]string{"syscall": "59", "key": "(null)", "ARCH": "x86_64", "SYSCALL": "execve"},
		},
		{
			name: "separator after numeric value",
			line: "type=PATH msg=audit(1.0:1): item=0 cap_frootid=0\x1dOUID=\"root\" OGID=\"root\"",
			want: map[string]string{"item": "0", "cap_frootid": "0", "OUID": "root", "OGID": "root"},
		},
		{
			name: "separator after hex value",
			line: "type=SYSCALL msg=audit(1.0:1): exe=2F746D702F612062\x1dARCH=x86_64",
			want: map[string]string{"exe": "/tmp/a b", "ARCH": "x86_64"},
		},
		{
			name: "separator before the first field",
			line: "type=SYSCALL msg=audit(1.0:1): \x1dARCH=x86_64",
			want: map[string]string{"ARCH": "x86_64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.line).Fields
			if len(got) != len(tt.want) {
				t.Errorf("got %d fields (%q), want %d", len(got), got, len(tt.want))
			}
			for key, want := range tt.want {
				if got[key] != want {
					t.Errorf("%s = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestParseLineQuotedMessage(t *testing.T) {
	tests := []struct {
		name, line string
		want       map[string]string
	}{
		{
			name: "raw format",
			line: `type=USER_LOGIN msg=audit(1.0:1): pid=10 uid=0 msg='op=login exe="/usr/sbin/sshd" hostname=? res=success'`,
			want: map[string]string{
				"pid": "10", "uid": "0", "op": "login", "exe": "/usr/sbin/sshd", "hostname": "?", "res": "success",
				"msg": `op=login exe="/usr/sbin/sshd" hostname=? res=success`,
			},
		},
		{
			name: "enriched format",
			line: "type=USER_LOGIN msg=audit(1.0:1): pid=10 msg='op=login res=success'\x1dUID=\"root\" AUID=\"neo\"",
			want: map[string]string{
				"pid": "10", "op": "login", "res": "success", "UID": "root", "AUID": "neo",
				"msg": "op=login res=success",
			},
		},
		{
			name: "last value is double-quoted",
			line: `type=USER_CMD msg=audit(1.0:1): msg='cwd="/home/a" res="failed"'`,
			want: map[string]string{"cwd": "/home/a", "res": "failed", "msg": `cwd="/home/a" res="failed"`},
		},
		{
			name: "apostrophe inside the message",
			line: `type=USER_ACCT msg=audit(1.0:1): msg='acct="o'brien" res=success'`,
			want: map[string]string{"acct": "o'brien", "res": "success", "msg": `acct="o'brien" res=success`},
		},
		{
			name: "apostrophe in an enriched field",
			line: "type=USER_ACCT msg=audit(1.0:1): msg='res=success'\x1dAUID=\"o'brien\"",
			want: map[string]string{"res": "success", "AUID": "o'brien", "msg": "res=success"},
		},
		{
			name: "hex value inside the message",
			line: `type=USER_CMD msg=audit(1.0:1): msg='exe=2F746D702F612062 res=success'`,
			want: map[string]string{"exe": "/tmp/a b", "res": "success", "msg": "exe=2F746D702F612062 res=success"},
		},
		{
			name: "free text only",
			line: `type=USER msg=audit(1.0:1): pid=10 msg='hello world'`,
			want: map[string]string{"pid": "10", "msg": "hello world"},
		},
		{
			name: "free text before fields",
			line: `type=USER_AVC msg=audit(1.0:1): msg='avc:  denied  { status } for auid=1000 hostname=?'`,
			want: map[string]string{"auid": "1000", "hostname": "?", "msg": "avc:  denied  { status } for auid=1000 hostname=?"},
		},
		{
			name: "truncated before the closing quote",
			line: `type=USER_LOGIN msg=audit(1.0:1): msg='op=login res=succ`,
			want: map[string]string{"op": "login", "res": "succ", "msg": "op=login res=succ"},
		},
		{
			name: "empty message",
			line: `type=USER msg=audit(1.0:1): pid=10 msg=''`,
			want: map[string]string{"pid": "10", "msg": ""},
		},
		{
			name: "unquoted msg is an ordinary field",
			line: `type=USER msg=audit(1.0:1): msg=plain pid=10`,
			want: map[string]string{"msg": "plain", "pid": "10"},
		},
		{
			name: "free text before a key without a message",
			line: `type=AVC msg=audit(1.0:1): avc:  denied  { read } for  pid=123 comm="x" permissive=0`,
			want: map[string]string{"pid": "123", "comm": "x", "permissive": "0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustParse(t, tt.line).Fields; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fields = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordGrouperKeepsInterleavedLinesTogether(t *testing.T) {
	grouper := newRecordGrouper()
	now := time.Now()
	for _, l := range []string{
		`type=SYSCALL msg=audit(1.0:1): key="one"`,
		`type=SYSCALL msg=audit(1.0:2): key="two"`,
		`type=EXECVE msg=audit(1.0:1): a0="one"`,
		`type=EXECVE msg=audit(1.0:2): a0="two"`,
	} {
		if completed := grouper.AddLine(mustParse(t, l), now); completed != nil {
			t.Fatalf("AddLine completed record %q early", completed.Key)
		}
	}

	records := grouper.Flush()
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	for i, wantKey := range []string{"1.0:1", "1.0:2"} {
		if records[i].Key != wantKey {
			t.Errorf("records[%d].Key = %q, want %q", i, records[i].Key, wantKey)
		}
		if len(records[i].Lines) != 2 {
			t.Errorf("records[%d] has %d lines, want 2", i, len(records[i].Lines))
		}
	}
}

func TestRecordGrouperExpireUsesLastLineTime(t *testing.T) {
	grouper := newRecordGrouper()
	start := time.Now()
	grouper.AddLine(mustParse(t, `type=SYSCALL msg=audit(1.0:1): key="active"`), start)
	grouper.AddLine(mustParse(t, `type=SYSCALL msg=audit(1.0:2): key="idle"`), start)
	grouper.AddLine(mustParse(t, `type=CWD msg=audit(1.0:1): cwd="/"`), start.Add(2*time.Second))

	expired := grouper.Expire(start.Add(time.Second))
	if len(expired) != 1 || expired[0].Key != "1.0:2" {
		t.Fatalf("Expire returned %d records (%v), want only 1.0:2", len(expired), expired)
	}

	// The expired ID starts a new record; the active one is still pending.
	grouper.AddLine(mustParse(t, `type=CWD msg=audit(1.0:2): cwd="/late"`), start.Add(2*time.Second))
	remaining := grouper.Flush()
	if len(remaining) != 2 {
		t.Fatalf("Flush returned %d records, want 2", len(remaining))
	}
	if got := grouper.Flush(); len(got) != 0 {
		t.Errorf("second Flush returned %d records, want 0", len(got))
	}
}

func TestRecordGrouperEvictsOldestAtLimit(t *testing.T) {
	grouper := newRecordGrouper()
	now := time.Now()
	for i := 0; i < maxPendingRecords; i++ {
		line := mustParse(t, fmt.Sprintf(`type=CWD msg=audit(1.0:%d): cwd="/"`, i))
		if completed := grouper.AddLine(line, now); completed != nil {
			t.Fatalf("AddLine evicted %q below the limit", completed.Key)
		}
	}

	evicted := grouper.AddLine(mustParse(t, `type=CWD msg=audit(1.0:99999): cwd="/"`), now)
	if evicted == nil || evicted.Key != "1.0:0" {
		t.Fatalf("evicted = %+v, want the oldest record 1.0:0", evicted)
	}
	if got := len(grouper.Flush()); got != maxPendingRecords {
		t.Errorf("Flush returned %d records, want %d", got, maxPendingRecords)
	}
}

func TestLineReaderHoldsPartialLineUntilNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, "first\nsec")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lines := newLineReader(f)

	if line, err := lines.next(); err != nil || line != "first" {
		t.Fatalf("next() = %q, %v; want first, nil", line, err)
	}
	if line, err := lines.next(); err != io.EOF || line != "" {
		t.Fatalf("next() at partial line = %q, %v; want empty, EOF", line, err)
	}

	appendLog(t, path, "ond\r\n")
	if line, err := lines.next(); err != nil || line != "second" {
		t.Fatalf("next() after completion = %q, %v; want second, nil", line, err)
	}
}

func TestLineReaderTruncatesLongLines(t *testing.T) {
	long := strings.Repeat("x", maxAuditLineBytes*3)
	lines := newLineReader(strings.NewReader(long + "\nnext\n"))

	line, err := lines.next()
	if err != nil {
		t.Fatal(err)
	}
	if len(line) != maxAuditLineBytes {
		t.Errorf("len(line) = %d, want %d", len(line), maxAuditLineBytes)
	}
	if line, err := lines.next(); err != nil || line != "next" {
		t.Errorf("line after long line = %q, %v; want next, nil", line, err)
	}
}

func TestReadFileContinuesPastBlankLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, `type=CWD msg=audit(1.0:1): cwd="/a"`+"\n\n"+`type=CWD msg=audit(2.0:2): cwd="/b"`+"\n")

	if got := readAll(t, path); len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
}

func TestReadFileReadsFinalLineWithoutNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, `type=CWD msg=audit(1.0:1): cwd="/a"`+"\n"+`type=CWD msg=audit(2.0:2): cwd="/b"`)

	got := readAll(t, path)
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if v := got[1].Value("cwd").String; v != "/b" {
		t.Errorf("last cwd = %q, want /b", v)
	}
}

func TestReadFileHandlesNodePrefixedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, `node=host1 type=SYSCALL msg=audit(1.0:1): key="k"`+"\n"+`node=host1 type=EXECVE msg=audit(1.0:1): a0="ls"`+"\n")

	got := readAll(t, path)
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if v := got[1].Value("key").String; v != "k" {
		t.Errorf("EXECVE key (from SYSCALL) = %q, want k", v)
	}
}

func TestLostEventsCountsUnparseableLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, "garbage\n"+`type=CWD msg=audit(1.0:1): cwd="/a"`+"\n")

	p := New(path)
	p.SetFollow(false)
	p.SendEvents(func(provider.Event) {})

	if got := p.LostEvents(); got != 1 {
		t.Errorf("LostEvents() = %d, want 1", got)
	}
}

func TestFollowSkipsHistoryAtStartup(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, `type=HISTORY msg=audit(1.0:1): n=1`+"\n")

	_, got := startFollowing(t, path, 20*time.Millisecond)
	waitUntilTailing(t, path, got)

	if n := got.count("HISTORY"); n != 0 {
		t.Errorf("got %d events from before startup, want 0", n)
	}
}

// A reader catching up with auditd sees EOF between a record's lines.
func TestFollowKeepsRecordTogetherAcrossEOF(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, "")

	_, got := startFollowing(t, path, time.Second)
	waitUntilTailing(t, path, got)

	appendLog(t, path, `type=SYSCALL msg=audit(5.0:1): key="k" exe="/bin/x"`+"\n")
	time.Sleep(100 * time.Millisecond)
	appendLog(t, path, `type=EXECVE msg=audit(5.0:1): a0="x"`+"\n")

	got.waitFor(t, "EXECVE event", func() bool { return got.count("EXECVE") == 1 })
	if v := got.ofType("EXECVE")[0].Value("key").String; v != "k" {
		t.Errorf("EXECVE key (from SYSCALL) = %q, want k", v)
	}
}

func TestFollowHoldsPartialLineUntilComplete(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, "")

	p, got := startFollowing(t, path, 20*time.Millisecond)
	waitUntilTailing(t, path, got)

	appendLog(t, path, `type=CWD msg=audit(5.0:1): cwd="/ha`)
	time.Sleep(50 * time.Millisecond)
	appendLog(t, path, `lf"`+"\n")

	got.waitFor(t, "CWD event", func() bool { return got.count("CWD") == 1 })
	if v := got.ofType("CWD")[0].Value("cwd").String; v != "/half" {
		t.Errorf("cwd = %q, want /half", v)
	}
	if n := p.LostEvents(); n != 0 {
		t.Errorf("LostEvents() = %d, want 0", n)
	}
}

func TestFollowSwitchesToNewFileAfterRotation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, "")

	_, got := startFollowing(t, path, 20*time.Millisecond)
	waitUntilTailing(t, path, got)

	// The first line may still be unread when the rename happens. The new file
	// already has a line in it when the tailer gets there.
	appendLog(t, path, `type=OLD msg=audit(5.0:1): n=1`+"\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, `type=NEW msg=audit(6.0:2): n=1`+"\n")
	got.waitFor(t, "events from both files", func() bool {
		return got.count("OLD") == 1 && got.count("NEW") == 1
	})

	// Later lines in the new file are followed as well, across a second rotation.
	appendLog(t, path, `type=NEW msg=audit(6.0:3): n=2`+"\n")
	got.waitFor(t, "second line in new file", func() bool { return got.count("NEW") == 2 })
	if err := os.Rename(path, path+".2"); err != nil {
		t.Fatal(err)
	}
	writeLog(t, path, `type=THIRD msg=audit(7.0:4): n=1`+"\n")
	got.waitFor(t, "event after second rotation", func() bool { return got.count("THIRD") == 1 })
}

func TestFollowWaitsForReplacementAfterRename(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, "")

	_, got := startFollowing(t, path, 20*time.Millisecond)
	waitUntilTailing(t, path, got)

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	writeLog(t, path, `type=NEW msg=audit(6.0:1): n=1`+"\n")

	got.waitFor(t, "event from replacement file", func() bool { return got.count("NEW") == 1 })
}

func TestFollowRestartsAfterTruncation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")
	writeLog(t, path, "")

	_, got := startFollowing(t, path, 20*time.Millisecond)
	waitUntilTailing(t, path, got)

	appendLog(t, path, `type=BEFORE msg=audit(5.0:1): padding="`+strings.Repeat("x", 256)+`"`+"\n")
	got.waitFor(t, "line before truncation", func() bool { return got.count("BEFORE") == 1 })

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendLog(t, path, `type=AFTER msg=audit(6.0:2): n=1`+"\n")

	got.waitFor(t, "line after truncation", func() bool { return got.count("AFTER") == 1 })
}

func TestFollowReadsFileCreatedAfterStartupFromTheBeginning(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")

	_, got := startFollowing(t, path, 20*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	writeLog(t, path, `type=CWD msg=audit(5.0:1): cwd="/late"`+"\n")

	got.waitFor(t, "event from late file", func() bool { return got.count("CWD") == 1 })
}

func TestCloseFlushesPendingRecords(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.log")

	// The file appears after startup so it is read from the beginning, and the
	// long idle timeout means only Close can emit the record.
	p := New(path)
	p.pollInterval = 5 * time.Millisecond
	p.idleTimeout = time.Hour
	got := &eventLog{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.SendEvents(got.add)
	}()

	time.Sleep(50 * time.Millisecond)
	// The garbage line comes last, so counting it proves the CWD line was read.
	writeLog(t, path, `type=CWD msg=audit(5.0:1): cwd="/pending"`+"\ngarbage\n")
	got.waitFor(t, "lines to be read", func() bool { return p.LostEvents() == 1 })
	if n := got.count("CWD"); n != 0 {
		t.Fatalf("got %d events before Close, want 0", n)
	}

	_ = p.Close()
	<-done
	if n := got.count("CWD"); n != 1 {
		t.Errorf("got %d events after Close, want 1", n)
	}
}

// eventLog collects events from a provider goroutine.
type eventLog struct {
	mu     sync.Mutex
	events []provider.Event
}

func (l *eventLog) add(event provider.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) ofType(recordType string) []provider.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var matched []provider.Event
	for _, event := range l.events {
		if event.Value("type").String == recordType {
			matched = append(matched, event)
		}
	}
	return matched
}

func (l *eventLog) count(recordType string) int {
	return len(l.ofType(recordType))
}

func (l *eventLog) waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startFollowing runs a provider in follow mode with a fast poll interval and
// stops it when the test ends.
func startFollowing(t *testing.T, path string, idleTimeout time.Duration) (*AuditProvider, *eventLog) {
	t.Helper()
	p := New(path)
	p.pollInterval = 5 * time.Millisecond
	p.idleTimeout = idleTimeout

	got := &eventLog{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.SendEvents(got.add)
	}()
	t.Cleanup(func() {
		_ = p.Close()
		<-done
	})
	return p, got
}

// waitUntilTailing appends marker records until one comes back, which proves the
// provider has opened the file and passed its startup seek.
func waitUntilTailing(t *testing.T, path string, got *eventLog) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for i := 1; got.count("MARKER") == 0; i++ {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the provider to start tailing")
		}
		appendLog(t, path, fmt.Sprintf("type=MARKER msg=audit(1.0:%d): n=%d\n", i, i))
		time.Sleep(20 * time.Millisecond)
	}
}

func writeLog(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendLog(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, path string) []provider.Event {
	t.Helper()
	p := New(path)
	p.SetFollow(false)
	var events []provider.Event
	p.SendEvents(func(event provider.Event) {
		events = append(events, event)
	})
	return events
}
