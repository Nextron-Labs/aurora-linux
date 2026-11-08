// This file provides stub types that will be replaced by bpf2go-generated code
// when `go generate` is run on a Linux system. It allows the package to compile
// on any OS for development and testing of the non-BPF components.
//
// On Linux, run `go generate ./lib/provider/ebpf/` to produce the real
// implementations in exec_monitor_bpfel.go, file_monitor_bpfel.go, and
// net_monitor_bpfel.go.

//go:build !linux

package ebpf

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
)

// execMonitorObjects holds the BPF objects for the exec monitor.
type execMonitorObjects struct {
	TraceSchedProcessExec *ciliumebpf.Program
	Events                *ciliumebpf.Map
	LostEvents            *ciliumebpf.Map
	SelfPids              *ciliumebpf.Map
}

func (o *execMonitorObjects) Close() error { return nil }

func loadExecMonitorObjects(objs *execMonitorObjects, opts *ciliumebpf.CollectionOptions) error {
	return fmt.Errorf("BPF programs are only available on Linux; run go generate on a Linux host")
}

// fileMonitorObjects holds the BPF objects for the file monitor.
type fileMonitorObjects struct {
	TraceSysEnterOpenat *ciliumebpf.Program
	TraceSysExitOpenat  *ciliumebpf.Program
	FileEvents          *ciliumebpf.Map
	FileLostEvents      *ciliumebpf.Map
	SelfPids            *ciliumebpf.Map
}

func (o *fileMonitorObjects) Close() error { return nil }

func loadFileMonitorObjects(objs *fileMonitorObjects, opts *ciliumebpf.CollectionOptions) error {
	return fmt.Errorf("BPF programs are only available on Linux; run go generate on a Linux host")
}

// netMonitorObjects holds the BPF objects for the network monitor.
type netMonitorObjects struct {
	TraceInetSockSetState *ciliumebpf.Program
	NetEvents             *ciliumebpf.Map
	NetLostEvents         *ciliumebpf.Map
	SelfPids              *ciliumebpf.Map
}

func (o *netMonitorObjects) Close() error { return nil }

func loadNetMonitorObjects(objs *netMonitorObjects, opts *ciliumebpf.CollectionOptions) error {
	return fmt.Errorf("BPF programs are only available on Linux; run go generate on a Linux host")
}

// bpfMonitorObjects holds the BPF objects for the bpf syscall monitor.
type bpfMonitorObjects struct {
	TraceSysEnterBpf *ciliumebpf.Program
	TraceSysExitBpf  *ciliumebpf.Program
	BpfEvents        *ciliumebpf.Map
	BpfLostEvents    *ciliumebpf.Map
	SelfPids         *ciliumebpf.Map
}

func (o *bpfMonitorObjects) Close() error { return nil }

func loadBpfMonitorObjects(objs *bpfMonitorObjects, opts *ciliumebpf.CollectionOptions) error {
	return fmt.Errorf("BPF programs are only available on Linux; run go generate on a Linux host")
}
