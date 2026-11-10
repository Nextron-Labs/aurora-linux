//go:build linux

package ebpf

import "golang.org/x/sys/unix"

type syscallStatfs = unix.Statfs_t

// statfsIsBPF reports whether dir is a mounted bpffs.
func statfsIsBPF(dir string, st *syscallStatfs) bool {
	return unix.Statfs(dir, st) == nil && st.Type == unix.BPF_FS_MAGIC
}
