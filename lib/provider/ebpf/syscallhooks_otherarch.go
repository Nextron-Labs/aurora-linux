//go:build linux && !386 && !amd64 && !arm64

package ebpf

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
)

// loadSyscallHooks: no per-ABI syscall entry hooks for this architecture;
// the sys_enter tracepoints are used instead.
func loadSyscallHooks() (*ciliumebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("syscall entry hooks are not built for this architecture")
}
