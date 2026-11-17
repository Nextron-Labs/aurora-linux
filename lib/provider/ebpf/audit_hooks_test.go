package ebpf

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

func hookEvent(op uint32, watchID uint32, path string, access accessPerm) *bpfHookEvent {
	e := &bpfHookEvent{Op: op, Pid: 4242, WatchID: watchID, Access: uint32(access)}
	copy(e.Path[:], path)
	e.PathLen = uint32(len(path) + 1)
	return e
}

func testRegistry(entries map[uint32]watchEntry, aliases ...pathAlias) *watchRegistry {
	r := newWatchRegistry(newWatchSet(defaultAuditWatches), nil, nil)
	r.entries = entries
	r.aliases = aliases
	return r
}

func names(events []provider.Event) []string {
	var out []string
	for _, e := range events {
		if e.Value("type").String == "PATH" {
			out = append(out, e.Value("name").String+"|"+e.Value("nametype").String)
		}
	}
	return out
}

func TestHookInodeHitUsesWatchedName(t *testing.T) {
	ws := newWatchSet(defaultAuditWatches)
	reg := testRegistry(map[uint32]watchEntry{7: {path: "/etc/ld.so.preload", flags: wFile, perms: permWA}})
	// A hard link elsewhere (or any other spelling) of the watched inode.
	ev := auditRecordsForHook(hookEvent(hookOpOpen, 7, "/tmp/innocent-link", permWrite), execProc("/bin/sh", "sh", 0), ws, reg, nil)
	if got := strings.Join(names(ev), ","); got != "/etc/ld.so.preload|NORMAL" {
		t.Fatalf("records = %s", got)
	}
	if ev[0].Value("resolved_name").String != "/tmp/innocent-link" {
		t.Fatalf("resolved_name missing: %v", ev[0].Value("resolved_name"))
	}
	// Read access does not satisfy a write/attr watch.
	if ev := auditRecordsForHook(hookEvent(hookOpOpen, 7, "/etc/ld.so.preload", permRead), execProc("/bin/sh", "sh", 0), ws, reg, nil); len(ev) != 0 {
		t.Fatalf("read of a wa-watched file produced %v", names(ev))
	}
}

func TestHookDirHitTranslatesAliasAndCreates(t *testing.T) {
	ws := newWatchSet(defaultAuditWatches)
	reg := testRegistry(map[uint32]watchEntry{3: {path: "/var/run", flags: wDir, perms: permAll}},
		pathAlias{canonical: "/run", literal: "/var/run"})
	var created []string
	ev := auditRecordsForHook(hookEvent(hookOpCreate, 3, "/run/haldrund.pid", permWrite),
		execProc("/tmp/x", "x", 0), ws, reg, func(n string) { created = append(created, n) })
	if got := strings.Join(names(ev), ","); got != "/var/run/haldrund.pid|CREATE" {
		t.Fatalf("records = %s", got)
	}
	if len(created) != 1 {
		t.Fatal("creation of a watched name must trigger a registry refresh")
	}
	// Unwatched creation in a watched directory is dropped.
	if ev := auditRecordsForHook(hookEvent(hookOpCreate, 3, "/run/unrelated.sock", permWrite), execProc("/x", "x", 0), ws, reg, nil); len(ev) != 0 {
		t.Fatalf("unwatched name produced %v", names(ev))
	}
}

func TestHookRenameAndMknod(t *testing.T) {
	ws := newWatchSet(defaultAuditWatches)
	reg := testRegistry(map[uint32]watchEntry{})
	e := hookEvent(hookOpRename, 0, "/tmp/staged", permWrite)
	copy(e.Path2[:], "/etc/systemd/system/evil.service")
	e.Path2Len = uint32(len("/etc/systemd/system/evil.service") + 1)
	ev := auditRecordsForHook(e, execProc("/usr/bin/mv", "mv", 0), ws, reg, nil)
	if got := strings.Join(names(ev), ","); got != "/etc/systemd/system/evil.service|CREATE" {
		t.Fatalf("rename records = %s", got)
	}
	ev = auditRecordsForHook(hookEvent(hookOpMknodSpecial, 0, "/tmp/fifo", permWrite), execProc("/usr/bin/mkfifo", "mkfifo", 0), ws, reg, nil)
	if len(ev) != 1 || ev[0].Value("SYSCALL").String != "mknod" || ev[0].Value("type").String != "SYSCALL" {
		t.Fatalf("mknod records = %v", ev)
	}
	// Zero path length must never yield a stale buffer.
	stale := &bpfHookEvent{Op: hookOpOpen, Pid: 1, Access: uint32(permWrite)}
	copy(stale.Path[:], "/etc/ld.so.preload")
	if ev := auditRecordsForHook(stale, execProc("/x", "x", 0), ws, reg, nil); len(ev) != 0 {
		t.Fatalf("stale path used: %v", names(ev))
	}
}

// PATH rules fire from security-hook events too (real Sigma rules).
func TestHookRecordsTriggerPathRules(t *testing.T) {
	dir := auditRulesDir(t)
	c := sigma.New(sigma.Config{RuleDirs: []string{dir}, MinLevel: "info", NoCollapseWS: true})
	if err := c.InitializeWithRules([]string{dir}); err != nil {
		t.Fatal(err)
	}
	ws := newWatchSet(defaultAuditWatches)
	reg := testRegistry(map[uint32]watchEntry{
		1: {path: "/etc/ld.so.preload", flags: wFile, perms: permWA},
		2: {path: "/etc/os-release", flags: wFile, perms: permRead},
	})
	cases := []struct {
		ev    *bpfHookEvent
		title string
	}{
		{hookEvent(hookOpOpen, 1, "//etc/../etc/ld.so.preload", permWrite), "Modification of ld.so.preload"},
		{hookEvent(hookOpOpen, 2, "/usr/lib/os-release", permRead), "System and Hardware Information Discovery"},
		{hookEvent(hookOpCreate, 0, "/etc/systemd/system/x.service", permWrite), "Systemd Service Creation"},
	}
	for _, tc := range cases {
		hit := false
		for _, e := range auditRecordsForHook(tc.ev, execProc("/bin/sh", "sh", 0), ws, reg, nil) {
			f := map[string]string{}
			e.ForEach(func(k, v string) { f[k] = v })
			for _, r := range c.EvalFieldsMap(f) {
				hit = hit || r.Title == tc.title
			}
		}
		if !hit {
			t.Errorf("%q not triggered by %s", tc.title, boundedStr(tc.ev.Path[:], tc.ev.PathLen))
		}
	}
}

func TestExpandPattern(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("etc/os-release")
	mk("etc/lsb-release")
	mk("etc/passwd")
	mk("etc/audit/rules.d/a.rules")
	mk("home/alice/.bashrc")
	mk("home/bob/notes")

	files, dirs, rec := expandPattern(root + "/etc/*release")
	sort.Strings(files)
	if strings.Join(files, ",") != root+"/etc/lsb-release,"+root+"/etc/os-release" || len(dirs) != 1 || len(rec) != 0 {
		t.Fatalf("glob leaf: files=%v dirs=%v rec=%v", files, dirs, rec)
	}
	files, dirs, rec = expandPattern(root + "/etc/audit/*")
	if len(files) != 1 || len(dirs) != 0 || len(rec) != 2 {
		t.Fatalf("recursive: files=%v dirs=%v rec=%v", files, dirs, rec)
	}
	files, dirs, _ = expandPattern(root + "/home/*/.bashrc")
	if len(files) != 1 || len(dirs) != 2 {
		t.Fatalf("wildcard dir: files=%v dirs=%v", files, dirs)
	}
	// Missing directory: watch the nearest existing ancestor recursively.
	files, dirs, rec = expandPattern(root + "/home/alice/.config/systemd/user/*")
	if len(files) != 0 || len(dirs) != 0 || len(rec) != 1 || rec[0] != root+"/home/alice" {
		t.Fatalf("missing dir: files=%v dirs=%v rec=%v", files, dirs, rec)
	}
}

func TestParseMountInfo(t *testing.T) {
	mi := `22 1 0:21 / / rw - btrfs /dev/sda2 rw
23 22 0:5 / /proc rw - proc proc rw
24 22 0:40 / /home rw - btrfs /dev/sda2 rw
25 22 0:41 / /mnt/with\040space rw - tmpfs tmpfs rw
26 22 0:50 / /home rw - tmpfs tmpfs rw
`
	mt := parseMountInfo(bufio.NewScanner(strings.NewReader(mi)))
	cases := map[string]uint32{
		"/etc/passwd":           0<<20 | 21,
		"/proc/version":         5,
		"/home/alice/.bashrc":   50, // stacked mount: the later one wins
		"/mnt/with space/x":     41,
		"/homeless/not-a-mount": 21,
	}
	for p, want := range cases {
		if got, ok := mt.devFor(p); !ok || got != want {
			t.Errorf("devFor(%s) = %d, %v; want %d", p, got, ok, want)
		}
	}
}

func TestSyscallHookRecordsAndCompatArch(t *testing.T) {
	ws := newWatchSet(defaultAuditWatches)
	reg := testRegistry(map[uint32]watchEntry{})
	e := &bpfHookEvent{Op: hookOpPersonality, Pid: 4242, Access: 0x40000, Flags: hookFlagCompat}
	ev := auditRecordsForHook(e, execProc("/tmp/x", "x", 0), ws, reg, nil)
	if len(ev) != 1 || ev[0].Value("SYSCALL").String != "personality" || ev[0].Value("a0").String != "40000" {
		t.Fatalf("personality record = %v", ev)
	}
	if arch := ev[0].Value("arch").String; arch != auditArchFor(true) || arch == auditArchFor(false) {
		t.Fatalf("compat arch = %s", arch)
	}
	for op, name := range map[uint32]string{hookOpSysinfo: "sysinfo", hookOpMemfdCreate: "memfd_create", hookOpDeleteModule: "delete_module"} {
		ev := auditRecordsForHook(&bpfHookEvent{Op: op, Pid: 1}, execProc("/x", "x", 0), ws, reg, nil)
		if len(ev) != 1 || ev[0].Value("SYSCALL").String != name || ev[0].Value("type").String != "SYSCALL" {
			t.Fatalf("%s record = %v", name, ev)
		}
	}
}

func TestPartialPathOnlyTrustedForDirectDirHits(t *testing.T) {
	ws := newWatchSet(defaultAuditWatches)
	reg := testRegistry(map[uint32]watchEntry{5: {path: "/etc/systemd/system", flags: wDir, perms: permWrite}})
	e := hookEvent(hookOpCreate, 5, "/system/evil.service", permWrite) // walk stopped early
	e.Flags = hookFlagPath1Partial
	if got := strings.Join(names(auditRecordsForHook(e, execProc("/x", "x", 0), ws, reg, nil)), ","); got != "/etc/systemd/system/evil.service|CREATE" {
		t.Fatalf("partial dir hit = %s", got)
	}
	// Partial path without a watched directory: never guessed.
	e = hookEvent(hookOpCreate, 0, "/etc/ld.so.preload", permWrite)
	e.Flags = hookFlagPath1Partial
	if ev := auditRecordsForHook(e, execProc("/x", "x", 0), ws, reg, nil); len(ev) != 0 {
		t.Fatalf("partial name hit attributed: %v", names(ev))
	}
}
