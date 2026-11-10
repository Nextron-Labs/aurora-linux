package ebpf

import (
	"fmt"
	"path"
	"strconv"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// Records for events from audit_hooks.c (fentry on LSM security hooks).

// Operation codes, identical to enum hook_op in audit_hooks.c.
const (
	hookOpOpen uint32 = 101 + iota
	hookOpCreate
	hookOpMknodSpecial
	hookOpMkdir
	hookOpUnlink
	hookOpRmdir
	hookOpRename
	hookOpLink
	hookOpSymlink
	hookOpSetattr
	hookOpTruncate
	hookOpConnect
	hookOpSyslog
	hookOpInitModule
	hookOpFinitModule
	hookOpSysinfo
	hookOpPersonality
	hookOpMemfdCreate
	hookOpDeleteModule
)

// hook_event.flags (HOOK_F_* in aurora_hooks.h)
const (
	hookFlagPath1Partial = 1
	hookFlagPath2Partial = 2
	hookFlagCompat       = 4
)

const hookPathBytes = 512

// bpfHookEvent mirrors struct hook_event in audit_hooks.c.
type bpfHookEvent struct {
	TimestampNs uint64
	StartNs     uint64
	ExecID      uint64
	Op          uint32
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	Euid        uint32
	Egid        uint32
	WatchID     uint32
	WatchID2    uint32
	Access      uint32
	Mode        uint32
	PathLen     uint32
	Path2Len    uint32
	Flags       uint32
	Comm        [16]byte
	Path        [hookPathBytes]byte
	Path2       [hookPathBytes]byte
}

const hookEventSize = 3*8 + 14*4 + 16 + 2*hookPathBytes

func decodeHookEvent(b []byte, e *bpfHookEvent) error {
	if len(b) < hookEventSize {
		return fmt.Errorf("hook event too short: %d < %d", len(b), hookEventSize)
	}
	e.TimestampNs = le.Uint64(b[0:])
	e.StartNs = le.Uint64(b[8:])
	e.ExecID = le.Uint64(b[16:])
	u := func(i int) uint32 { return le.Uint32(b[24+4*i:]) }
	e.Op, e.Pid, e.Ppid, e.Uid, e.Gid, e.Euid, e.Egid = u(0), u(1), u(2), u(3), u(4), u(5), u(6)
	e.WatchID, e.WatchID2, e.Access, e.Mode = u(7), u(8), u(9), u(10)
	e.PathLen, e.Path2Len, e.Flags = u(11), u(12), u(13)
	copy(e.Comm[:], b[80:96])
	copy(e.Path[:], b[96:96+hookPathBytes])
	copy(e.Path2[:], b[96+hookPathBytes:96+2*hookPathBytes])
	return nil
}

// boundedStr returns the kernel string honouring its length; a zero length
// means "no string" (never fall back to the whole buffer).
func boundedStr(b []byte, n uint32) string {
	if n == 0 {
		return ""
	}
	return nullTermStr(b, int(n))
}

var hookSyscallNames = map[uint32]string{
	hookOpOpen: "openat", hookOpCreate: "openat", hookOpMknodSpecial: "mknod",
	hookOpMkdir: "mkdir", hookOpUnlink: "unlink", hookOpRmdir: "rmdir",
	hookOpRename: "rename", hookOpLink: "link", hookOpSymlink: "symlink",
	hookOpSetattr: "chmod", hookOpTruncate: "ftruncate", hookOpConnect: "connect",
	hookOpSyslog: "syslog", hookOpInitModule: "init_module", hookOpFinitModule: "finit_module",
	hookOpSysinfo: "sysinfo", hookOpPersonality: "personality", hookOpMemfdCreate: "memfd_create",
	hookOpDeleteModule: "delete_module",
}

// hookPathItem is one PATH record candidate.
type hookPathItem struct {
	kernelPath string
	watchID    uint32
	nameType   string
	access     accessPerm
	partial    bool // the in-kernel walk stopped before the root (legacy kernels)
}

// auditRecordsForHook converts one hook event to auditd-shaped records.
// created receives the names of watched objects that were just created so
// the registry can start watching their inodes.
func auditRecordsForHook(raw *bpfHookEvent, p *auditProc, watches *watchSet, reg *watchRegistry,
	created func(name string)) []provider.Event {

	name, ok := hookSyscallNames[raw.Op]
	if !ok {
		return nil
	}
	p.syscallName = name
	p.syscallNr = 0
	p.compat = raw.Flags&hookFlagCompat != 0

	switch raw.Op {
	case hookOpSysinfo, hookOpMemfdCreate, hookOpDeleteModule:
		return []provider.Event{p.syscallRecord()}
	case hookOpPersonality:
		a := [4]uint64{uint64(raw.Access)}
		p.a = &a
		return []provider.Event{p.syscallRecord()}
	case hookOpConnect:
		ip, port, v6, ok := sockaddrDest(raw.Path[:min(int(raw.PathLen), len(raw.Path))])
		if !ok {
			return nil
		}
		p.key = connectKey(v6)
		rec := p.syscallRecord()
		rec.fields.AddField("daddr", ip)
		rec.fields.AddField("dport", strconv.Itoa(int(port)))
		rec.fields.AddField("saddr", fmt.Sprintf("%x", raw.Path[:min(int(raw.PathLen), len(raw.Path))]))
		return []provider.Event{rec}
	case hookOpSyslog:
		a := [4]uint64{uint64(raw.Access)}
		p.a = &a
		return []provider.Event{p.syscallRecord()}
	case hookOpInitModule, hookOpFinitModule:
		return []provider.Event{p.syscallRecord()}
	}

	var items []hookPathItem
	path1 := boundedStr(raw.Path[:], raw.PathLen)
	path2 := boundedStr(raw.Path2[:], raw.Path2Len)
	partial1 := raw.Flags&hookFlagPath1Partial != 0
	partial2 := raw.Flags&hookFlagPath2Partial != 0
	switch raw.Op {
	case hookOpOpen:
		items = []hookPathItem{{path1, raw.WatchID, "NORMAL", accessPerm(raw.Access), partial1}}
	case hookOpCreate, hookOpMknodSpecial, hookOpMkdir, hookOpSymlink:
		items = []hookPathItem{{path1, raw.WatchID, "CREATE", permWrite, partial1}}
	case hookOpUnlink, hookOpRmdir:
		items = []hookPathItem{{path1, raw.WatchID, "DELETE", permWrite, partial1}}
	case hookOpRename:
		items = []hookPathItem{{path1, raw.WatchID, "DELETE", permWrite, partial1}, {path2, raw.WatchID2, "CREATE", permWrite, partial2}}
	case hookOpLink:
		items = []hookPathItem{{path1, raw.WatchID, "NORMAL", permWrite, partial1}, {path2, raw.WatchID2, "CREATE", permWrite, partial2}}
	case hookOpSetattr:
		items = []hookPathItem{{path1, raw.WatchID, "NORMAL", permAttr, false}}
	case hookOpTruncate:
		items = []hookPathItem{{path1, raw.WatchID, "NORMAL", permWrite, partial1}}
	}

	var events []provider.Event
	if raw.Op == hookOpMknodSpecial {
		// lnx_auditd_susp_special_file_creation_via_mknod_syscall
		events = append(events, p.syscallRecord())
	}
	for i, it := range items {
		recName, key, ok := resolveHookName(it, watches, reg)
		if !ok {
			continue
		}
		if it.nameType == "CREATE" && created != nil {
			created(recName)
		}
		pp := *p
		pp.key = key
		pp.a = nil
		rec := pp.baseFields("PATH")
		rec.AddField("item", strconv.Itoa(i))
		rec.AddField("name", recName)
		rec.AddField("nametype", it.nameType)
		if it.kernelPath != "" && it.kernelPath != recName {
			// The path the process actually used (hard link, symlink, other
			// spelling); the watch matched by inode.
			rec.AddField("resolved_name", it.kernelPath)
		}
		events = append(events, pp.event(rec))
	}
	return events
}

// resolveHookName decides the PATH name of an item and whether a watch rule
// covers it. Inode hits use the watched file's own name (any alias of the
// inode is the same object); directory/name hits use the canonical kernel
// path, translated back to the spelling the rules use.
func resolveHookName(it hookPathItem, watches *watchSet, reg *watchRegistry) (name, key string, ok bool) {
	if e, found := reg.entry(it.watchID); found && e.flags&wFile != 0 && it.nameType != "CREATE" {
		if key, ok := watches.match(e.path, it.access); ok {
			return e.path, key, true
		}
	}
	if it.kernelPath == "" {
		return "", "", false
	}
	if it.partial {
		// Legacy kernels: the walk stopped before the root, so only the leaf
		// is reliable. A direct hit on a watched directory still yields the
		// full name; anything else cannot be attributed safely.
		e, found := reg.entry(it.watchID)
		if !found || e.flags&wDir == 0 {
			return "", "", false
		}
		full := path.Join(e.path, path.Base(it.kernelPath))
		if key, ok := watches.match(full, it.access); ok {
			return full, key, true
		}
		return "", "", false
	}
	translated := reg.translate(it.kernelPath)
	if key, ok := watches.match(translated, it.access); ok {
		return translated, key, true
	}
	if translated != it.kernelPath {
		if key, ok := watches.match(it.kernelPath, it.access); ok {
			return it.kernelPath, key, true
		}
	}
	return "", "", false
}
