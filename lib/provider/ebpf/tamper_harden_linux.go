//go:build linux

package ebpf

import (
	"os"

	"golang.org/x/sys/unix"
)

// HardenSelf makes the running process harder to kill or inspect: it is
// marked non-dumpable (blocks ptrace/memory access by same-uid non-root and
// core dumps) and made the OOM killer's last choice. It returns the problems it
// could not work around.
func HardenSelf() []error {
	var errs []error
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		errs = append(errs, err)
	}
	// -900, not -1000: with -1000 and a memory limit (MemoryMax) the cgroup
	// OOM killer would have no victim and Aurora could hang in reclaim
	// instead of being restarted.
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-900"), 0o644); err != nil {
		errs = append(errs, err)
	}
	return errs
}
