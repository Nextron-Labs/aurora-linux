package ebpf

import (
	"bufio"
	"os"
	"path"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// BPFObjectIDs are kernel IDs of BPF objects owned by Aurora.
type BPFObjectIDs struct {
	Programs []uint32
	Maps     []uint32
	Links    []uint32
}

func (ids *BPFObjectIDs) Merge(o BPFObjectIDs) {
	ids.Programs = append(ids.Programs, o.Programs...)
	ids.Maps = append(ids.Maps, o.Maps...)
	ids.Links = append(ids.Links, o.Links...)
}

func (ids *BPFObjectIDs) addProgram(p *ebpf.Program) {
	if id, ok := programID(p); ok {
		ids.Programs = append(ids.Programs, uint32(id))
	}
}

func (ids *BPFObjectIDs) addMap(m *ebpf.Map) {
	if m == nil {
		return
	}
	info, err := m.Info()
	if err != nil {
		return
	}
	if id, ok := info.ID(); ok {
		ids.Maps = append(ids.Maps, uint32(id))
	}
}

func (ids *BPFObjectIDs) addMaps(ms ...*ebpf.Map) {
	for _, m := range ms {
		ids.addMap(m)
	}
}

func (ids *BPFObjectIDs) addLinks(links ...link.Link) {
	for _, l := range links {
		if l == nil {
			continue
		}
		if info, err := l.Info(); err == nil {
			ids.Links = append(ids.Links, uint32(info.ID))
		}
	}
}

func (ids *BPFObjectIDs) addCollection(c *ebpf.Collection) {
	if c == nil {
		return
	}
	for _, p := range c.Programs {
		ids.addProgram(p)
	}
	for _, m := range c.Maps {
		ids.addMap(m)
	}
}

func programID(p *ebpf.Program) (ebpf.ProgramID, bool) {
	if p == nil {
		return 0, false
	}
	info, err := p.Info()
	if err != nil {
		return 0, false
	}
	return info.ID()
}

func collectionProgramIDs(c *ebpf.Collection) []ebpf.ProgramID {
	var ids []ebpf.ProgramID
	if c == nil {
		return ids
	}
	for _, p := range c.Programs {
		if id, ok := programID(p); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// OwnObjects returns the IDs of every BPF program, map and link the listener
// created.
func (l *Listener) OwnObjects() BPFObjectIDs {
	var ids BPFObjectIDs
	// bpf2go objects: listed explicitly (compile-checked) — their embedded
	// Programs/Maps structs have unexported types, so reflection cannot be
	// used to enumerate them.
	if o := l.execObjs; o != nil {
		ids.addProgram(o.TraceSchedProcessExec)
		ids.addMaps(o.Events, o.LostEvents, o.SelfPids)
	}
	if o := l.fileObjs; o != nil {
		ids.addProgram(o.TraceSysEnterOpenat)
		ids.addProgram(o.TraceSysExitOpenat)
		ids.addMaps(o.FileEvents, o.FileLostEvents, o.OpenatArgs, o.SelfPids, o.WatchedDirs)
	}
	if o := l.netObjs; o != nil {
		ids.addProgram(o.TraceInetSockSetState)
		ids.addMaps(o.NetEvents, o.NetLostEvents, o.SelfPids)
	}
	if o := l.bpfObjs; o != nil {
		ids.addProgram(o.TraceSysEnterBpf)
		ids.addProgram(o.TraceSysExitBpf)
		ids.addMaps(o.BpfArgs, o.BpfEvents, o.BpfLostEvents, o.SelfPids)
	}
	ids.addCollection(l.auditColl)
	ids.addCollection(l.hookColl)
	ids.addCollection(l.scColl)
	ids.addCollection(l.exeColl)
	ids.addLinks(l.execLink, l.fileEnter, l.fileExit, l.netLink, l.bpfEnter, l.bpfExit, l.exeLink)
	ids.addLinks(l.auditLinks...)
	ids.addLinks(l.hookLinks...)
	return ids
}

// ControlFileKeys returns the inodes of files that can kill, freeze or
// starve Aurora: its cgroup v2 control files and its OOM score.
func ControlFileKeys() []hookInodeKey {
	mt := loadMountTable()
	var paths []string
	if cg := ownCgroupDir(); cg != "" {
		for _, f := range []string{
			"cgroup.kill", "cgroup.freeze", "cgroup.procs", "cgroup.threads", "cgroup.type",
			"cgroup.subtree_control", "cgroup.max.depth", "cgroup.max.descendants",
			"memory.max", "memory.high", "memory.oom.group", "cpu.max", "cpu.weight",
			"cpu.idle", "pids.max", "io.max", "io.weight",
		} {
			paths = append(paths, path.Join(cg, f))
		}
	}
	paths = append(paths, "/proc/self/oom_score_adj", "/proc/self/oom_adj")
	var keys []hookInodeKey
	for _, p := range paths {
		if k, ok := inodeKeyFor(p, mt); ok {
			keys = append(keys, k)
		}
	}
	return keys
}

// ownCgroupDir returns Aurora's cgroup v2 directory under /sys/fs/cgroup.
func ownCgroupDir() string {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			dir := path.Join("/sys/fs/cgroup", rest)
			if st, err := os.Stat(dir); err == nil && st.IsDir() {
				return dir
			}
		}
	}
	return ""
}
