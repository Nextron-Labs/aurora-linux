package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RunState tracks whether the previous Aurora instance terminated cleanly.
// A "running" marker that survives into the next start means the previous
// instance was killed (SIGKILL, OOM, crash) without a chance to alert.
type RunState struct{ Path string }

// PreviousRun describes the previous instance as recorded in the state file.
type PreviousRun struct {
	UncleanPid int       // non-zero if it did not shut down cleanly
	PrevStart  time.Time // when it started (zero if unknown)
	// SelfExit is set when the previous instance exited on purpose so the
	// service manager restarts it (e.g. "blind-source"); UncleanPid is 0.
	SelfExit    string
	SelfExitPid int
}

// Begin records that this instance is running and returns what is known
// about the previous one.
func (r RunState) Begin() PreviousRun {
	var prev PreviousRun
	if raw, err := os.ReadFile(r.Path); err == nil {
		f := strings.Fields(string(raw))
		if len(f) >= 2 && f[0] == "running" {
			prev.UncleanPid, _ = strconv.Atoi(f[1])
		}
		if len(f) >= 4 && f[0] == "selfexit" {
			prev.SelfExitPid, _ = strconv.Atoi(f[1])
			prev.SelfExit = f[3]
		}
		if len(f) >= 3 {
			if ns, err := strconv.ParseInt(f[2], 10, 64); err == nil {
				prev.PrevStart = time.Unix(0, ns)
			}
		}
	}
	_ = os.MkdirAll(filepath.Dir(r.Path), 0o700)
	_ = os.WriteFile(r.Path, []byte(fmt.Sprintf("running %d %d\n", os.Getpid(), time.Now().UnixNano())), 0o600)
	return prev
}

// End marks a clean shutdown (the start time is kept for the next instance).
func (r RunState) End() {
	raw, err := os.ReadFile(r.Path)
	if err != nil {
		return
	}
	f := strings.Fields(string(raw))
	if len(f) >= 3 {
		_ = os.WriteFile(r.Path, []byte("clean 0 "+f[2]+"\n"), 0o600)
		return
	}
	_ = os.Remove(r.Path)
}

// SelfExit records that this instance is exiting on purpose (reason must be
// a single token) so the next one does not report it as killed.
func (r RunState) SelfExit(reason string) {
	raw, err := os.ReadFile(r.Path)
	if err != nil {
		return
	}
	f := strings.Fields(string(raw))
	if len(f) >= 3 && f[0] == "running" && !strings.ContainsAny(reason, " \t\n") && reason != "" {
		_ = os.WriteFile(r.Path, []byte(fmt.Sprintf("selfexit %s %s %s\n", f[1], f[2], reason)), 0o600)
	}
}
