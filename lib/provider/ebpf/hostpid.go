package ebpf

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// DiscoverHostPID returns Aurora's tgid in the root pid namespace, which is
// what BPF programs see. It equals os.Getpid() unless Aurora runs inside a
// pid namespace. On failure it falls back to os.Getpid().
func DiscoverHostPID() (uint32, error) {
	self := uint32(os.Getpid())
	spec, err := loadWhoami()
	if err != nil {
		return self, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return self, err
	}
	defer coll.Close()

	lnk, err := link.Tracepoint("syscalls", "sys_enter_getpgid", coll.Programs["whoami_getpgid"], nil)
	if err != nil {
		return self, err
	}
	defer lnk.Close()

	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return self, err
	}
	// A positive pid that cannot exist (> PID_MAX_LIMIT 4194304): getpgid fails
	// with ESRCH and has no side effects.
	magic := uint64(binary.LittleEndian.Uint32(b[:])&0x3FFFFFFF) | 0x40000000
	m := coll.Maps["whoami"]
	if err := m.Put(uint32(0), magic); err != nil {
		return self, err
	}
	_, _ = syscall.Getpgid(int(magic))

	var host uint64
	if err := m.Lookup(uint32(1), &host); err != nil || host == 0 {
		return self, fmt.Errorf("whoami probe did not fire")
	}
	return uint32(host), nil
}
