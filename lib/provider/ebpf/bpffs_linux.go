//go:build linux

package ebpf

import "golang.org/x/sys/unix"

type syscallStatfs = unix.Statfs_t

// statfsIsBPF reports whether dir is a mounted bpffs. Type is int32 on 32-bit
// architectures, where BPF_FS_MAGIC (0xCAFE4A11) overflows, so compare as uint32.
func statfsIsBPF(dir string, st *syscallStatfs) bool {
	return unix.Statfs(dir, st) == nil && uint32(st.Type) == unix.BPF_FS_MAGIC
}
