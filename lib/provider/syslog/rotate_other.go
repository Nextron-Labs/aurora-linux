//go:build !linux

package syslog

import (
	"os"
	"syscall"
)

func inodeOf(*os.File) uint64 { return 0 }

func rotated(path string, f *os.File, _ uint64) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	pos, err := f.Seek(0, 1)
	return err == nil && st.Size() < pos
}

func childProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{} }
