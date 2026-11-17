//go:build linux

package ebpf

import (
	"time"

	"golang.org/x/sys/unix"
)

// fileBirthTime returns the creation time of name when the filesystem
// reports it (statx STATX_BTIME).
func fileBirthTime(name string) (time.Time, bool) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, name, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &st); err != nil {
		return time.Time{}, false
	}
	if st.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}, false
	}
	return time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)), true
}
