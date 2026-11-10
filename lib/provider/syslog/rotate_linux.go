//go:build linux

package syslog

import (
	"os"
	"syscall"
)

func inodeOf(f *os.File) uint64 {
	if st, err := f.Stat(); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			return s.Ino
		}
	}
	return 0
}

// rotated reports whether path now refers to a different file or the file was
// truncated below our read position.
func rotated(path string, f *os.File, ino uint64) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false // missing for a moment during rotation: keep the old fd
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok && ino != 0 && s.Ino != ino {
		return true
	}
	pos, err := f.Seek(0, 1)
	return err == nil && st.Size() < pos
}

// childProcAttr kills journalctl if Aurora dies.
func childProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
