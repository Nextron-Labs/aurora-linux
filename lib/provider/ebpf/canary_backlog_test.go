package ebpf

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// A reader still draining older events is lagging, not blind; once it
// reaches the helper's events the canary is seen and the round passes.
func TestCanaryBacklogIsNotBlindness(t *testing.T) {
	c := &Canary{}
	run := &canaryRun{pid: 42, seen: map[string]bool{}}
	exited := time.Now()
	var calls atomic.Int32
	progress := func(src string, since time.Time) (bool, bool, uint64) {
		if calls.Add(1) == 5 {
			// The backlog drains: the canary event is finally processed.
			c.mu.Lock()
			run.seen[SourceProcessExec] = true
			c.mu.Unlock()
		}
		return false, false, uint64(calls.Load())
	}
	res := c.await(run, []string{SourceProcessExec}, exited, 10*time.Millisecond, 5*time.Second, progress, nil)
	if len(res.Missing) != 0 || len(res.Lagging) != 0 {
		t.Fatalf("backlogged then delivered: got %+v, want pass", res)
	}
}

func TestCanaryPersistentBacklogReportsLag(t *testing.T) {
	c := &Canary{}
	run := &canaryRun{pid: 42, seen: map[string]bool{}}
	var tok atomic.Uint64
	progress := func(string, time.Time) (bool, bool, uint64) { return false, false, tok.Add(1) }
	res := c.await(run, []string{SourceProcessExec}, time.Now(), 10*time.Millisecond, 400*time.Millisecond, progress, nil)
	if len(res.Missing) != 0 || !slices.Equal(res.Lagging, []string{SourceProcessExec}) {
		t.Fatalf("got %+v, want lagging only", res)
	}
}

// A reader that processed a newer event (or sits idle on an empty ring)
// without delivering the canary is blind.
func TestCanaryCaughtUpReaderIsBlind(t *testing.T) {
	c := &Canary{}
	run := &canaryRun{pid: 42, seen: map[string]bool{SourceNetConnect: true}}
	progress := func(src string, _ time.Time) (bool, bool, uint64) {
		switch src {
		case SourceProcessExec:
			return true, true, 7 // processed a newer event
		default:
			return true, false, 3 // idle with an empty ring, no progress
		}
	}
	start := time.Now()
	res := c.await(run, []string{SourceProcessExec, SourceFileCreate, SourceNetConnect}, start,
		10*time.Millisecond, 5*time.Second, progress, nil)
	if !slices.Equal(res.Missing, []string{SourceProcessExec, SourceFileCreate}) || len(res.Lagging) != 0 {
		t.Fatalf("got %+v", res)
	}
	if time.Since(start) < canaryIdleConfirm {
		t.Fatal("idle verdict must be confirmed over canaryIdleConfirm")
	}
}

// An idle snapshot whose token keeps changing (records still flowing) must
// not be confirmed.
func TestCanaryIdleNeedsStableToken(t *testing.T) {
	c := &Canary{}
	run := &canaryRun{pid: 42, seen: map[string]bool{}}
	var tok atomic.Uint64
	progress := func(string, time.Time) (bool, bool, uint64) { return true, false, tok.Add(1) }
	res := c.await(run, []string{SourceFileCreate}, time.Now(), 10*time.Millisecond, 600*time.Millisecond, progress, nil)
	if len(res.Missing) != 0 || len(res.Lagging) != 1 {
		t.Fatalf("got %+v, want lagging", res)
	}
}

func TestReaderProgressSnapshot(t *testing.T) {
	var p readerProgress
	pending := 10
	p.setRing(func() int { return pending })
	since := time.Now()
	if s, _, _ := p.settledSnapshot(since); s {
		t.Fatal("busy reader with pending bytes must not be settled")
	}
	p.processed(since.Add(-time.Second))
	if s, _, _ := p.settledSnapshot(since); s {
		t.Fatal("an older event does not settle the reader")
	}
	p.processed(since.Add(time.Millisecond))
	if s, d, _ := p.settledSnapshot(since); !s || !d {
		t.Fatal("a newer event settles the reader definitively")
	}
	var q readerProgress
	q.setRing(func() int { return pending })
	q.beginRead()
	if s, _, _ := q.settledSnapshot(since); s {
		t.Fatal("waiting with pending bytes is not idle")
	}
	pending = 0
	if s, d, _ := q.settledSnapshot(since); !s || d {
		t.Fatal("waiting on an empty ring is idle (non-definitive)")
	}
}

func TestRunStateSelfExitIsNotUnclean(t *testing.T) {
	r := RunState{Path: t.TempDir() + "/state"}
	r.Begin()
	r.SelfExit("blind-source")
	prev := r.Begin()
	if prev.UncleanPid != 0 || prev.SelfExit != "blind-source" || prev.SelfExitPid == 0 {
		t.Fatalf("got %+v", prev)
	}
	// The instance after that one ran normally until killed: unclean again.
	prev = r.Begin()
	if prev.UncleanPid == 0 || prev.SelfExit != "" {
		t.Fatalf("got %+v", prev)
	}
}

func TestCanaryAbortsOnStop(t *testing.T) {
	c := &Canary{}
	run := &canaryRun{pid: 42, seen: map[string]bool{}}
	stop := make(chan struct{})
	time.AfterFunc(200*time.Millisecond, func() { close(stop) })
	start := time.Now()
	progress := func(string, time.Time) (bool, bool, uint64) { return false, false, 1 }
	res := c.await(run, []string{SourceProcessExec}, time.Now(), 10*time.Millisecond, time.Minute, progress, stop)
	if time.Since(start) > 5*time.Second || len(res.Missing)+len(res.Lagging) != 0 {
		t.Fatalf("not aborted: %+v after %v", res, time.Since(start))
	}
}
