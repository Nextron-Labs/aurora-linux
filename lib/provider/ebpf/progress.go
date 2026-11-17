package ebpf

import (
	"sync/atomic"
	"time"
)

// readerProgress tracks how far a ring-buffer reader has processed, so the
// tamper canary can tell a blinded source (its events never reach the
// ring) from a merely backlogged one (events queued behind a slow
// consumer on a starved host).
type readerProgress struct {
	waiting atomic.Bool                // blocked in ReadInto
	done    atomic.Uint64              // records fully processed
	lastTs  atomic.Int64               // wall time (unix ns) of the last processed event
	avail   atomic.Pointer[func() int] // bytes pending in the ring (nil: unknown)
}

// setRing registers the ring's fill-level function.
func (p *readerProgress) setRing(avail func() int) { p.avail.Store(&avail) }

func (p *readerProgress) beginRead() { p.waiting.Store(true) }
func (p *readerProgress) endRead()   { p.waiting.Store(false) }

// processed marks one record finished; ts is the event's own time (zero if
// unknown).
func (p *readerProgress) processed(ts time.Time) {
	if !ts.IsZero() {
		p.lastTs.Store(ts.UnixNano())
	}
	p.done.Add(1)
}

// settledSnapshot reports whether every event that entered the ring before
// since has been processed: the reader handled a later event, or it is idle
// with an empty ring. The returned token changes whenever the reader makes
// progress; callers confirm an idle verdict by seeing the same token again
// later (a record popped right before the check is then accounted for).
func (p *readerProgress) settledSnapshot(since time.Time) (settled, definitive bool, token uint64) {
	token = p.done.Load()
	if p.lastTs.Load() >= since.UnixNano() {
		return true, true, token
	}
	if f := p.avail.Load(); f != nil && p.waiting.Load() && (*f)() == 0 {
		return true, false, token
	}
	return false, false, token
}

// Reader names (see readerFor).
const (
	progExec  = "exec"
	progFile  = "file"
	progNet   = "net"
	progAudit = "audit"
	progHook  = "hook"
	progBpf   = "bpf"
)

func (l *Listener) progress(name string) *readerProgress {
	l.progOnce.Do(func() {
		l.prog = map[string]*readerProgress{}
		for _, n := range []string{progExec, progFile, progNet, progAudit, progHook, progBpf} {
			l.prog[n] = &readerProgress{}
		}
	})
	return l.prog[name]
}

// readerFor names the reader that delivers a source's canary events.
func (l *Listener) readerFor(source string) string {
	switch source {
	case SourceProcessExec:
		return progExec
	case SourceFileCreate:
		return progFile
	case SourceNetConnect:
		return progNet
	case SourceAudit:
		// The canary's sysinfo record comes from the syscall entry hook
		// when it attached, else from the tracepoint monitor.
		if l.hookRd != nil && l.sysinfoViaHook {
			return progHook
		}
		return progAudit
	}
	return ""
}

// SourceProgress is the canary's view of a source's reader (see
// readerProgress.settledSnapshot).
func (l *Listener) SourceProgress(source string, since time.Time) (settled, definitive bool, token uint64) {
	n := l.readerFor(source)
	if n == "" {
		return true, true, 0
	}
	return l.progress(n).settledSnapshot(since)
}
