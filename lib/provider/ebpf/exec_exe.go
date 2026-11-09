package ebpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

// execExeInfo mirrors struct exe_info in exec_exe.c.
type execExeInfo struct {
	ExecID uint64
	Len    uint32
	Pad    uint32
	Path   [execExePathBytes]byte
}

// initExecExe loads the optional in-kernel exe path resolver. Failure only
// means Image falls back to /proc/PID/exe.
func (l *Listener) initExecExe() {
	spec, err := loadExecExe()
	if err != nil {
		return
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.WithError(err).Debug("In-kernel exe path resolver unavailable (needs bpf_loop, kernel 5.17+)")
		return
	}
	lnk, err := link.Tracepoint("sched", "sched_process_exec", coll.Programs["exec_exe_path"], nil)
	if err != nil {
		coll.Close()
		return
	}
	l.exeColl, l.exeLink = coll, lnk
}

// kernelExePath returns the image path the kernel resolved for this exec, or
// "" if unknown. The entry is consumed.
func (l *Listener) kernelExePath(pid uint32, execID uint64) string {
	if l.exeColl == nil {
		return ""
	}
	m := l.exeColl.Maps["exe_paths"]
	var info execExeInfo
	if err := m.LookupAndDelete(pid, &info); err != nil {
		return ""
	}
	if execID != 0 && info.ExecID != execID {
		return ""
	}
	return boundedStr(info.Path[:], info.Len)
}

// peekKernelExePath returns the exe path recorded at the process's last exec
// without consuming it ("" if unknown or already consumed by the exec
// reader).
// execID, when non-zero, must match the recorded exec generation.
func (l *Listener) peekKernelExePath(pid uint32, execID uint64) string {
	if l.exeColl == nil {
		return ""
	}
	var info execExeInfo
	if err := l.exeColl.Maps["exe_paths"].Lookup(pid, &info); err != nil {
		return ""
	}
	if execID != 0 && info.ExecID != execID {
		return ""
	}
	return boundedStr(info.Path[:], info.Len)
}

// processImage returns the image of the process behind a non-exec event.
// Short-lived processes (touch, curl, ...) are often gone from /proc by the
// time userland reads the event, and their exec event may still be queued
// in another reader; the in-kernel exec record covers that window.
func (l *Listener) processImage(pid uint32) string {
	if image, _ := readExeLink(pid); image != "" {
		return image
	}
	if image := l.peekKernelExePath(pid, 0); image != "" {
		return image
	}
	if l.correlator != nil {
		if info := l.correlator.Lookup(pid); info != nil {
			return info.Image
		}
	}
	return ""
}
