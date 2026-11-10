package ebpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// Audit-compatible event emission.
//
// The SigmaHQ linux/auditd rules match on raw auditd record fields (type,
// SYSCALL, exe, comm, key, a0..aN, name, nametype, ...). The functions in this
// file synthesise exactly those records from eBPF data so Aurora does not
// depend on a running auditd.

const (
	// SourceAudit enables auditd-compatible record emission from eBPF.
	SourceAudit = "LinuxEBPF:Audit"

	// EventIDAuditRecord identifies auditd-shaped records. Sigma auditd rules
	// never inspect EventID.
	EventIDAuditRecord uint16 = 200

	// auditArgsMax is the argv capture size of exec_monitor.c (MAX_ARGS).
	auditArgsMax = 4096
	// watchKeyBytes is WATCH_KEY_BYTES of audit_monitor.c.
	watchKeyBytes = 64

	auditUnsetID = "4294967295"
)

// Operation codes, identical to enum audit_op in audit_monitor.c.
const (
	auditOpOpen uint32 = iota + 1
	auditOpOpenat
	auditOpOpenat2
	auditOpCreat
	auditOpTruncate
	auditOpMkdir
	auditOpMkdirat
	auditOpRmdir
	auditOpUnlink
	auditOpUnlinkat
	auditOpRename
	auditOpRenameat
	auditOpRenameat2
	auditOpLink
	auditOpLinkat
	auditOpSymlink
	auditOpSymlinkat
	auditOpChmod
	auditOpFchmodat
	auditOpFchmodat2
	auditOpChown
	auditOpLchown
	auditOpFchownat
	auditOpUtimensat
	auditOpMknod
	auditOpMknodat
	auditOpSysinfo
	auditOpSyslog
	auditOpPersonality
	auditOpMemfdCreate
	auditOpInitModule
	auditOpFinitModule
	auditOpDeleteModule
	auditOpConnect
)

// open(2) flag bits (identical on amd64 and arm64).
const (
	oAccMode = 0o3
	oWronly  = 0o1
	oRdwr    = 0o2
	oCreat   = 0o100
	oExcl    = 0o200
	oTrunc   = 0o1000
	oAppend  = 0o2000
)

const atFDCWD = -100

// opKind selects how an operation is turned into records.
type opKind uint8

const (
	kindPath  opKind = iota // PATH record(s) for the named object
	kindPlain               // SYSCALL record only
	kindConnect
)

// auditOpInfo describes how a BPF operation maps to audit records.
type auditOpInfo struct {
	syscall string // SYSCALL name as auditd would print it
	kind    opKind
	// emitSyscall also emits a SYSCALL record in addition to PATH records.
	emitSyscall bool
	// access is the permission class used for watch matching.
	access accessPerm
	// create/delete describe nametype of path (first) and path2 (second).
	nameType1, nameType2 string
}

var auditOps = map[uint32]auditOpInfo{
	auditOpOpen:      {syscall: "open", kind: kindPath},
	auditOpOpenat:    {syscall: "openat", kind: kindPath},
	auditOpOpenat2:   {syscall: "openat2", kind: kindPath},
	auditOpCreat:     {syscall: "creat", kind: kindPath, access: permWrite, nameType1: "CREATE"},
	auditOpTruncate:  {syscall: "truncate", kind: kindPath, access: permWrite},
	auditOpMkdir:     {syscall: "mkdir", kind: kindPath, access: permWrite, nameType1: "CREATE"},
	auditOpMkdirat:   {syscall: "mkdirat", kind: kindPath, access: permWrite, nameType1: "CREATE"},
	auditOpRmdir:     {syscall: "rmdir", kind: kindPath, access: permWrite, nameType1: "DELETE"},
	auditOpUnlink:    {syscall: "unlink", kind: kindPath, access: permWrite, nameType1: "DELETE"},
	auditOpUnlinkat:  {syscall: "unlinkat", kind: kindPath, access: permWrite, nameType1: "DELETE"},
	auditOpRename:    {syscall: "rename", kind: kindPath, access: permWrite, nameType1: "DELETE", nameType2: "CREATE"},
	auditOpRenameat:  {syscall: "renameat", kind: kindPath, access: permWrite, nameType1: "DELETE", nameType2: "CREATE"},
	auditOpRenameat2: {syscall: "renameat2", kind: kindPath, access: permWrite, nameType1: "DELETE", nameType2: "CREATE"},
	auditOpLink:      {syscall: "link", kind: kindPath, access: permWrite, nameType1: "NORMAL", nameType2: "CREATE"},
	auditOpLinkat:    {syscall: "linkat", kind: kindPath, access: permWrite, nameType1: "NORMAL", nameType2: "CREATE"},
	auditOpSymlink:   {syscall: "symlink", kind: kindPath, access: permWrite, nameType1: "CREATE"},
	auditOpSymlinkat: {syscall: "symlinkat", kind: kindPath, access: permWrite, nameType1: "CREATE"},
	auditOpChmod:     {syscall: "chmod", kind: kindPath, access: permAttr},
	auditOpFchmodat:  {syscall: "fchmodat", kind: kindPath, access: permAttr},
	auditOpFchmodat2: {syscall: "fchmodat2", kind: kindPath, access: permAttr},
	auditOpChown:     {syscall: "chown", kind: kindPath, access: permAttr},
	auditOpLchown:    {syscall: "lchown", kind: kindPath, access: permAttr},
	auditOpFchownat:  {syscall: "fchownat", kind: kindPath, access: permAttr},
	auditOpUtimensat: {syscall: "utimensat", kind: kindPath, access: permAttr},
	// mknodat is reported as "mknod": modern libc implements mknod(3) with
	// mknodat(2), and the Sigma rule only knows the "mknod" syscall name.
	auditOpMknod:        {syscall: "mknod", kind: kindPath, emitSyscall: true, access: permWrite, nameType1: "CREATE"},
	auditOpMknodat:      {syscall: "mknod", kind: kindPath, emitSyscall: true, access: permWrite, nameType1: "CREATE"},
	auditOpSysinfo:      {syscall: "sysinfo", kind: kindPlain},
	auditOpSyslog:       {syscall: "syslog", kind: kindPlain},
	auditOpPersonality:  {syscall: "personality", kind: kindPlain},
	auditOpMemfdCreate:  {syscall: "memfd_create", kind: kindPlain},
	auditOpInitModule:   {syscall: "init_module", kind: kindPlain},
	auditOpFinitModule:  {syscall: "finit_module", kind: kindPlain},
	auditOpDeleteModule: {syscall: "delete_module", kind: kindPlain},
	auditOpConnect:      {syscall: "connect", kind: kindConnect},
}

// bpfAuditEvent mirrors struct audit_event in audit_monitor.c.
type bpfAuditEvent struct {
	TimestampNs uint64
	Op          uint32
	Nr          uint32
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	Euid        uint32
	Egid        uint32
	Dfd         int32
	Dfd2        int32
	Flags       uint32
	PathLen     uint32
	Path2Len    uint32
	Pad         uint32
	Args        [4]uint64
	Comm        [16]byte
	Path        [256]byte
	Path2       [256]byte
	StartNs     uint64
}

// auditProc carries the process attributes shared by all records of one
// event (the equivalent of the SYSCALL record that auditd merges into every
// other record of the event).
type auditProc struct {
	pid, ppid            uint32
	uid, gid, euid, egid uint32
	auid                 string
	comm, exe            string
	syscallName          string
	syscallNr            uint32
	key                  string
	a                    *[4]uint64 // raw syscall arguments, nil if unknown
	cwd                  string
	ts                   time.Time
	compat               bool // 32-bit (compat) syscall entry
}

// auditArchFor returns auditd's arch value (AUDIT_ARCH_*) for the native or
// the 32-bit compat ABI.
func auditArchFor(compat bool) string {
	switch {
	case runtime.GOARCH == "arm64" && compat:
		return "40000028" // ARM
	case runtime.GOARCH == "arm64":
		return "c00000b7"
	case compat:
		return "40000003" // i386
	default:
		return "c000003e"
	}
}

// execSyscallNr is the execve(2) number for the running architecture.
func execSyscallNr() uint32 {
	if runtime.GOARCH == "arm64" {
		return 221
	}
	return 59
}

// baseFields builds the fields shared by every record of an event.
func (p *auditProc) baseFields(recType string) enrichment.DataFieldsMap {
	f := make(enrichment.DataFieldsMap, 24)
	f.AddField("type", recType)
	f.AddField("arch", auditArchFor(p.compat))
	f.AddField("syscall", strconv.FormatUint(uint64(p.syscallNr), 10))
	f.AddField("SYSCALL", p.syscallName)
	f.AddField("success", "yes")
	f.AddField("pid", strconv.FormatUint(uint64(p.pid), 10))
	f.AddField("ppid", strconv.FormatUint(uint64(p.ppid), 10))
	f.AddField("auid", p.auid)
	f.AddField("uid", strconv.FormatUint(uint64(p.uid), 10))
	f.AddField("gid", strconv.FormatUint(uint64(p.gid), 10))
	f.AddField("euid", strconv.FormatUint(uint64(p.euid), 10))
	f.AddField("egid", strconv.FormatUint(uint64(p.egid), 10))
	f.AddField("comm", p.comm)
	f.AddField("exe", p.exe)
	if p.key != "" {
		f.AddField("key", p.key)
	}
	return f
}

func (p *auditProc) event(f enrichment.DataFieldsMap) *ebpfEvent {
	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDAuditRecord,
		},
		pid:    p.pid,
		source: SourceAudit,
		ts:     p.ts,
		fields: f,
	}
}

func hexArg(v uint64) string { return strconv.FormatUint(v, 16) }

// syscallRecord builds the SYSCALL record.
func (p *auditProc) syscallRecord() *ebpfEvent {
	f := p.baseFields("SYSCALL")
	if p.a != nil {
		for i, v := range p.a {
			f.AddField("a"+strconv.Itoa(i), hexArg(v))
		}
	}
	return p.event(f)
}

// ---------------------------------------------------------------------------
// exec: SYSCALL + EXECVE + PATH (+ synthesised SERVICE_STOP / ADD_USER)
// ---------------------------------------------------------------------------

// splitArgv splits a kernel argv block (NUL separated) into arguments.
func splitArgv(block []byte) []string {
	if len(block) == 0 {
		return nil
	}
	parts := strings.Split(string(block), "\x00")
	// The block ends with the NUL terminating the last argument.
	if n := len(parts); n > 0 && parts[n-1] == "" {
		parts = parts[:n-1]
	}
	return parts
}

// auditRecordsForExec returns the auditd-shaped records for one execve.
func auditRecordsForExec(p *auditProc, filename string, argv []string) []provider.Event {
	p.syscallName = "execve"
	p.syscallNr = execSyscallNr()
	p.key = execKey(p.exe)
	if k := execKey(filename); k != "" {
		p.key = k
	}

	events := make([]provider.Event, 0, 4)
	events = append(events, p.syscallRecord())

	execve := p.baseFields("EXECVE")
	execve.AddField("argc", strconv.Itoa(len(argv)))
	for i, a := range argv {
		execve.AddField("a"+strconv.Itoa(i), a)
	}
	// auditd's PROCTITLE record carries the whole command line; several Sigma
	// keyword rules (e.g. "--to-ports 42") rely on seeing it as one value.
	execve.AddField("proctitle", strings.Join(argv, " "))
	events = append(events, p.event(execve))

	name := filename
	if name != "" && !path.IsAbs(name) && p.cwd != "" {
		name = path.Join(p.cwd, name)
	}
	pathRec := p.baseFields("PATH")
	pathRec.AddField("item", "0")
	pathRec.AddField("name", name)
	pathRec.AddField("nametype", "NORMAL")
	events = append(events, p.event(pathRec))

	events = append(events, synthesiseUserlandRecords(p, argv)...)
	return events
}

// serviceStopVerbs are systemctl verbs that stop a unit.
var serviceStopVerbs = map[string]struct{}{
	"stop": {}, "disable": {}, "mask": {}, "kill": {},
}

// synthesiseUserlandRecords produces the records auditd gets from userspace
// (systemd and shadow-utils talk to the audit netlink socket directly, which
// has no kernel-side tracepoint). They are inferred from the command line.
func synthesiseUserlandRecords(p *auditProc, argv []string) []provider.Event {
	if len(argv) == 0 {
		return nil
	}
	var out []provider.Event
	exeBase := path.Base(p.exe)
	argBase := path.Base(argv[0])

	// SERVICE_STOP: systemd logs it when a unit stops. Infer it from the
	// service-management front-ends that cause it.
	for _, unit := range stoppedUnitsFor(argBase, path.Dir(argv[0]), argv[1:]) {
		f := p.baseFields("SERVICE_STOP")
		f.AddField("unit", unit)
		f.AddField("res", "success")
		out = append(out, p.event(f))
	}

	// ADD_USER: logged by useradd/adduser through the audit netlink socket.
	if exeBase == "useradd" || exeBase == "adduser" || argBase == "useradd" || argBase == "adduser" {
		f := p.baseFields("ADD_USER")
		if acct := newAccountName(argv[1:]); acct != "" {
			f.AddField("acct", acct)
		}
		f.AddField("res", "success")
		out = append(out, p.event(f))
	}
	return out
}

func trimUnit(u string) string {
	return strings.TrimSuffix(path.Base(u), ".service")
}

// systemctlValueFlags are systemctl options that take a separate value
// (the value must not be mistaken for the verb or a unit).
var systemctlValueFlags = map[string]bool{
	"-H": true, "--host": true, "-M": true, "--machine": true, "-s": true, "--signal": true,
	"--kill-whom": true, "--kill-value": true, "-p": true, "--property": true, "-t": true,
	"--type": true, "--state": true, "-o": true, "--output": true, "-n": true, "--lines": true,
	"--root": true, "--image": true, "--job-mode": true, "--what": true, "--timestamp": true,
	"--preset-mode": true, "--marked": false, "--when": true, "--message": true,
	"--drop-in": true, "--image-policy": true, "--reboot-argument": true,
}

// stoppedUnits extracts unit names stopped by systemctl / service / ufw /
// rc-service / SysV init scripts.
func stoppedUnits(cmd string, args []string) []string {
	return stoppedUnitsFor(cmd, "", args)
}

// stoppedUnitsFor is stoppedUnits with the directory of argv[0], used to
// restrict the "<script> stop" form to init script directories.
func stoppedUnitsFor(cmd, dir string, args []string) []string {
	var units []string
	switch cmd {
	case "systemctl":
		verb := ""
		var rest []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			if strings.HasPrefix(a, "-") {
				if systemctlValueFlags[a] && !strings.Contains(a, "=") {
					i++ // skip the option's value
				}
				continue
			}
			if verb == "" {
				verb = a
				continue
			}
			rest = append(rest, a)
		}
		if _, ok := serviceStopVerbs[verb]; ok {
			for _, u := range rest {
				units = append(units, trimUnit(u))
			}
		}
	case "service":
		var plain []string
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				plain = append(plain, a)
			}
		}
		if len(plain) >= 2 && plain[1] == "stop" {
			units = append(units, trimUnit(plain[0]))
		}
	case "ufw":
		for _, a := range args {
			if a == "disable" {
				units = append(units, "ufw")
			}
		}
	case "rc-service":
		if len(args) >= 2 && args[1] == "stop" {
			units = append(units, trimUnit(args[0]))
		}
	default:
		// SysV init script: /etc/init.d/<unit> stop (not "docker stop c")
		if (dir == "/etc/init.d" || dir == "/etc/rc.d/init.d" || dir == "") && len(args) >= 1 && args[0] == "stop" &&
			(dir != "" || cmd == "iptables" || cmd == "ip6tables" || cmd == "firewalld" || cmd == "ufw") {
			units = append(units, trimUnit(cmd))
		}
	}
	return units
}

// useraddValueFlags are useradd/adduser options taking a value.
var useraddValueFlags = map[string]bool{
	"-b": true, "--base-dir": true, "-c": true, "--comment": true, "-d": true, "--home-dir": true,
	"-e": true, "--expiredate": true, "-f": true, "--inactive": true, "-g": true, "--gid": true,
	"-G": true, "--groups": true, "-k": true, "--skel": true, "-K": true, "--key": true,
	"-p": true, "--password": true, "-R": true, "--root": true, "-P": true, "--prefix": true,
	"-s": true, "--shell": true, "-u": true, "--uid": true, "-Z": true, "--selinux-user": true,
	"--home": true, "--ingroup": true, "--gecos": true, "--firstuid": true, "--lastuid": true,
}

// newAccountName returns the account a useradd/adduser command line creates.
func newAccountName(args []string) string {
	acct := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if useraddValueFlags[a] {
				i++
			}
			continue
		}
		acct = a
	}
	return acct
}

// ---------------------------------------------------------------------------
// syscall events from audit_monitor.c
// ---------------------------------------------------------------------------

// accessFromOpenFlags translates open(2) flags to an audit permission class.
func accessFromOpenFlags(flags uint32) accessPerm {
	var perm accessPerm
	switch flags & oAccMode {
	case oWronly:
		perm = permWrite
	case oRdwr:
		perm = permRead | permWrite
	default:
		perm = permRead
	}
	if flags&(oCreat|oTrunc|oAppend) != 0 {
		perm |= permWrite
	}
	return perm
}

func isOpenOp(op uint32) bool {
	return op == auditOpOpen || op == auditOpOpenat || op == auditOpOpenat2
}

// auditPathName returns the absolute (lexically cleaned) path an audit PATH
// record would carry. auditd logs the name as given by the process and uses
// CWD records for resolution; Aurora resolves up-front so rules can match
// absolute names. Symlinks are intentionally not followed (the watch is on
// the name the process used).
func auditPathName(pid uint32, name string, dfd int32) string {
	if name == "" || path.IsAbs(name) {
		if name == "" {
			return name
		}
		return path.Clean(name)
	}
	var base string
	if dfd == atFDCWD {
		base, _ = readCwd(pid)
	} else {
		base, _ = readFdLink(pid, dfd)
	}
	if base == "" {
		return name
	}
	return filepath.Clean(filepath.Join(base, name))
}

// sockaddrDest decodes the raw sockaddr copied by the connect probe.
func sockaddrDest(raw []byte) (ip string, port uint16, isV6 bool, ok bool) {
	if len(raw) < 8 {
		return "", 0, false, false
	}
	family := binary.LittleEndian.Uint16(raw[0:2])
	port = binary.BigEndian.Uint16(raw[2:4])
	switch family {
	case 2:
		if len(raw) < 8 {
			return "", 0, false, false
		}
		addr := netip.AddrFrom4([4]byte{raw[4], raw[5], raw[6], raw[7]})
		return addr.String(), port, false, true
	case 10:
		if len(raw) < 24 {
			return "", 0, true, false
		}
		var a [16]byte
		copy(a[:], raw[8:24])
		return netip.AddrFrom16(a).String(), port, true, true
	}
	return "", 0, false, false
}

// auditRecordsForSyscall converts one audit_monitor event to audit records.
// birth reports the creation time of a file (used to decide nametype=CREATE
// for O_CREAT opens); it may be nil.
func auditRecordsForSyscall(
	raw *bpfAuditEvent,
	p *auditProc,
	watches *watchSet,
	birth func(name string) (time.Time, bool),
) []provider.Event {
	info, ok := auditOps[raw.Op]
	if !ok {
		return nil
	}
	p.syscallName = info.syscall
	p.syscallNr = raw.Nr
	a := raw.Args
	p.a = &a

	switch info.kind {
	case kindPlain:
		p.key = ""
		return []provider.Event{p.syscallRecord()}

	case kindConnect:
		n := int(raw.PathLen)
		if n > len(raw.Path) {
			n = len(raw.Path)
		}
		ip, port, v6, ok := sockaddrDest(raw.Path[:n])
		if !ok {
			return nil
		}
		p.key = connectKey(v6)
		rec := p.syscallRecord()
		f := rec.fields
		f.AddField("daddr", ip)
		f.AddField("dport", strconv.Itoa(int(port)))
		f.AddField("saddr", fmt.Sprintf("%x", raw.Path[:n]))
		return []provider.Event{rec}
	}

	// kindPath
	var events []provider.Event
	if info.emitSyscall {
		p.key = ""
		events = append(events, p.syscallRecord())
	}

	// SYSCALL-level argument values are not meaningful for PATH records.
	p.a = nil

	access := info.access
	nameType1, nameType2 := info.nameType1, info.nameType2
	if isOpenOp(raw.Op) {
		access = accessFromOpenFlags(raw.Flags)
	}

	emit := func(name string, dfd int32, nameType string, item int, createHint bool) {
		abs := auditPathName(raw.Pid, name, dfd)
		if abs == "" {
			return
		}
		key, ok := watches.match(abs, access)
		if !ok {
			return
		}
		if createHint && birth != nil {
			// O_CREAT only means "create if missing": confirm via the
			// birth time that this call actually created the file.
			if bt, known := birth(abs); known {
				d := p.ts.Sub(bt)
				if d < -2*time.Second || d > 2*time.Second {
					nameType = "NORMAL"
				}
			}
		}
		if nameType == "" {
			nameType = "NORMAL"
		}
		pp := *p
		pp.key = key
		rec := pp.baseFields("PATH")
		rec.AddField("item", strconv.Itoa(item))
		rec.AddField("name", abs)
		rec.AddField("nametype", nameType)
		events = append(events, pp.event(rec))
	}

	name1 := cstr(raw.Path[:], int(raw.PathLen))
	if name1 != "" {
		createHint := false
		if isOpenOp(raw.Op) && raw.Flags&oCreat != 0 {
			nameType1 = "CREATE"
			createHint = true
		}
		emit(name1, raw.Dfd, nameType1, 0, createHint)
	}
	if raw.Path2Len > 0 {
		name2 := cstr(raw.Path2[:], int(raw.Path2Len))
		if name2 != "" {
			emit(name2, raw.Dfd2, nameType2, 1, false)
		}
	}
	return events
}

// cstr extracts a NUL-terminated string honouring the kernel-reported length.
func cstr(b []byte, n int) string {
	if n <= 0 {
		return "" // never fall back to the whole (possibly stale) buffer
	}
	return nullTermStr(b, n)
}
