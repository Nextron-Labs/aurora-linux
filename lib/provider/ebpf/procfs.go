package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxCmdlineBytes = 32768
	loginUIDUnset   = "4294967295"
)

// readExeLink resolves /proc/PID/exe symlink to the real binary path.
func readExeLink(pid uint32) (string, error) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	// Kernel appends " (deleted)" if the binary was unlinked after exec
	link = strings.TrimSuffix(link, " (deleted)")
	return link, nil
}

// readCmdline reads /proc/PID/cmdline and returns the raw NUL-separated bytes.
func readCmdline(pid uint32) ([]byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCmdlineBytes {
		data = data[:maxCmdlineBytes]
	}
	return data, nil
}

// readCwd resolves /proc/PID/cwd symlink.
func readCwd(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
}

// readLoginUID reads /proc/PID/loginuid.
// Returns empty string if the value is unset (4294967295).
func readLoginUID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if s == loginUIDUnset {
		return ""
	}
	return s
}

// readFdLink resolves /proc/PID/fd/N symlink — used for dfd resolution.
func readFdLink(pid uint32, fd int32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
}

// resolveFilename resolves a potentially relative filename using dfd.
// If filename is absolute, it is returned directly (with symlinks evaluated).
// If dfd == AT_FDCWD (-100), it is resolved relative to the process cwd.
// Otherwise it is resolved relative to the directory referenced by dfd.
func resolveFilename(pid uint32, filename string, dfd int32) string {
	if filepath.IsAbs(filename) {
		resolved, err := filepath.EvalSymlinks(filename)
		if err != nil {
			return filename
		}
		return resolved
	}

	var base string
	const atFDCWD = -100
	if dfd == atFDCWD {
		cwd, err := readCwd(pid)
		if err != nil {
			return filename
		}
		base = cwd
	} else {
		fdPath, err := readFdLink(pid, dfd)
		if err != nil {
			return filename
		}
		base = fdPath
	}

	full := filepath.Join(base, filename)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return full
	}
	return resolved
}

// clockTickNs is the length of one USER_HZ tick in /proc/PID/stat (always 100 Hz on Linux).
const clockTickNs = 10_000_000

// parseStatStartTicks extracts field 22 (starttime, in clock ticks since boot)
// from the contents of /proc/PID/stat. The command name (field 2) may contain
// spaces and parentheses, so parsing starts after the last ')'.
func parseStatStartTicks(stat string) (uint64, bool) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(stat[i+1:])
	// f[0] is field 3 (state); starttime is field 22 => f[19].
	if len(f) < 20 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	return v, err == nil
}

// startMatches reports whether /proc's start time for a process equals the
// kernel-reported start time (within one tick), i.e. the pid still refers to
// the same process.
func startMatches(procStartTicks, kernelStartNs uint64) bool {
	procNs := procStartTicks * clockTickNs
	d := int64(procNs) - int64(kernelStartNs)
	if d < 0 {
		d = -d
	}
	return d <= 2*clockTickNs
}

// readStartTicks reads the start time of pid from /proc/PID/stat.
func readStartTicks(pid uint32) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	return parseStatStartTicks(string(data))
}

// readCmdlineIfSame returns /proc/PID/cmdline only if pid still refers to the
// process that started at startNs (no pid reuse).
func readCmdlineIfSame(pid uint32, startNs uint64) ([]byte, bool) {
	ticks, ok := readStartTicks(pid)
	if !ok || !startMatches(ticks, startNs) {
		return nil, false
	}
	b, err := readCmdline(pid)
	if err != nil {
		return nil, false
	}
	// Re-check: the process may have exited and the pid been reused while we
	// read.
	if t2, ok := readStartTicks(pid); !ok || t2 != ticks {
		return nil, false
	}
	return b, true
}
