package ebpf

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// Canary helper protocol (argv[1]):
//
//	CanaryArg       stage 1: wait for "go <nonce>" on stdin, then re-exec as stage 2
//	CanaryStage2Arg stage 2: exercise the sensors and exit
//
// The helper is identified only by its pid, which Aurora registers before
// releasing it; the re-exec makes its exec event happen after registration.
// No content (argv, file names) is used to recognise canary events, so
// other processes cannot get their events hidden by imitating the canary.
const (
	CanaryArg       = "__aurora_canary__"
	CanaryStage2Arg = "__aurora_canary_stage2__"
	canaryNonceEnv  = "AURORA_CANARY_NONCE"

	canaryNetPort       = "9"
	canaryHelperTimeout = 5 * time.Second
	// canaryGrace keeps suppressing late events of the helper (they can
	// arrive from another ring after the round ended).
	canaryGrace = 3 * time.Second
)

// Canary periodically runs a harmless helper process that exec's, creates a
// file, calls sysinfo(2) and connects to 127.0.0.1:9, then verifies that the
// corresponding events arrive. A source that stays silent has been blinded
// (detached program, altered hook, ...).
type Canary struct {
	// AuroraPid is Aurora's pid as the kernel reports it in events (host
	// pid namespace). While a helper is being spawned (before its pid is
	// known), exec events whose parent is Aurora are the helper's first
	// exec and are hidden.
	AuroraPid uint32

	mu       sync.Mutex
	spawning bool
	spawnPid uint32 // host pid of the helper, learned from its first exec
	run      *canaryRun
	// active is the lock-free fast path of Observe: almost always false.
	active atomic.Bool
	// pid and deadline of the previous round's helper (grace period).
	lastPid   uint32
	lastUntil time.Time
}

type canaryRun struct {
	pid  uint32
	seen map[string]bool
}

// classify reports which source an event from the helper proves alive.
func classify(e provider.Event) (string, bool) {
	switch e.Source() {
	case SourceProcessExec:
		// Only the post-registration exec (stage 2) proves the sensor.
		return SourceProcessExec, strings.Contains(e.Value("CommandLine").String, CanaryStage2Arg)
	case SourceFileCreate:
		return SourceFileCreate, true
	case SourceNetConnect:
		return SourceNetConnect, e.Value("DestinationPort").String == canaryNetPort
	case SourceAudit:
		return SourceAudit, e.Value("SYSCALL").String == "sysinfo"
	}
	return "", false
}

// Observe must see every event first. It returns true if the event was
// produced by the canary helper and must not be processed further.
func (c *Canary) Observe(e provider.Event) bool {
	if !c.active.Load() {
		return false
	}
	pid := e.Process()
	c.mu.Lock()
	defer c.mu.Unlock()
	if r := c.run; r != nil && pid == r.pid && pid != 0 {
		if src, ok := classify(e); ok {
			r.seen[src] = true
		}
		return true
	}
	if pid != 0 && pid == c.lastPid && time.Now().Before(c.lastUntil) {
		return true
	}
	if c.spawning && c.AuroraPid != 0 && eventParent(e) == c.AuroraPid {
		if e.Source() == SourceProcessExec && c.spawnPid == 0 {
			c.spawnPid = pid
		}
		return true
	}
	return false
}

// helperHostPid returns the helper's pid as kernel events report it. In the
// host pid namespace that is the pid Aurora sees; inside a container it
// differs, and is learned from the helper's first exec (parent = Aurora).
func (c *Canary) helperHostPid(nsPid uint32) uint32 {
	if c.AuroraPid == 0 || c.AuroraPid == uint32(os.Getpid()) {
		return nsPid
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		p := c.spawnPid
		c.mu.Unlock()
		if p != 0 {
			return p
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nsPid
}

// eventParent returns the parent pid of an exec-related event (0 if none).
func eventParent(e provider.Event) uint32 {
	v := e.Value("ParentProcessId").String
	if v == "" {
		v = e.Value("ppid").String
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// ProgressFunc reports whether a source's reader has processed everything
// that entered its ring before since (see Listener.SourceProgress).
type ProgressFunc func(source string, since time.Time) (settled, definitive bool, token uint64)

// CanaryResult is the outcome of one round.
type CanaryResult struct {
	// Missing sources: the reader caught up past the helper's events and
	// none of them arrived. The source is blind.
	Missing []string
	// Lagging sources: no canary event yet, but the reader is still
	// draining older events (overloaded host or slow consumers).
	Lagging []string
}

const (
	// canarySettleMargin: an event this much younger than the helper's
	// exit proves its reader is past the helper's events (ring order and
	// clock skew between the ring's producers).
	canarySettleMargin = 250 * time.Millisecond
	// canaryIdleConfirm: an idle, empty ring must stay so (no progress)
	// this long before its silence counts.
	canaryIdleConfirm = 300 * time.Millisecond
)

// Check runs one canary round for the given sources. A source missing its
// canary event after timeout is reported Missing only once its reader has
// provably caught up; a reader still behind after maxBacklog is reported
// Lagging instead. progress may be nil (no backlog awareness).
// Closing stop aborts the round (shutdown); the result is then empty.
func (c *Canary) Check(sources []string, timeout, maxBacklog time.Duration, progress ProgressFunc,
	stop <-chan struct{}) (CanaryResult, error) {
	var nb [8]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return CanaryResult{}, err
	}
	nonce := hex.EncodeToString(nb[:])

	// /proc/self/exe keeps working if the binary was replaced or deleted on
	// disk.
	cmd := exec.Command("/proc/self/exe", CanaryArg)
	cmd.Env = []string{canaryNonceEnv + "=" + nonce}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return CanaryResult{}, err
	}
	run := &canaryRun{seen: map[string]bool{}}

	// The helper's first exec happens inside Start, before its pid is
	// known: hide Aurora's children's execs until it is registered.
	c.mu.Lock()
	c.spawning, c.spawnPid = true, 0
	c.mu.Unlock()
	c.active.Store(true)
	if err := cmd.Start(); err != nil {
		c.mu.Lock()
		c.spawning = false
		if c.run == nil && time.Now().After(c.lastUntil) {
			c.active.Store(false)
		}
		c.mu.Unlock()
		return CanaryResult{}, fmt.Errorf("starting canary: %w", err)
	}
	// A stuck helper must never hang the guard (or leak a process).
	watchdog := time.AfterFunc(canaryHelperTimeout, func() { _ = cmd.Process.Kill() })
	defer watchdog.Stop()

	run.pid = c.helperHostPid(uint32(cmd.Process.Pid))
	c.mu.Lock()
	c.run = run
	c.spawning = false
	c.mu.Unlock()
	c.active.Store(true)
	defer func() {
		c.mu.Lock()
		c.lastPid, c.lastUntil = run.pid, time.Now().Add(canaryGrace)
		c.run = nil
		c.mu.Unlock()
		// Keep the fast path open for the grace period.
		time.AfterFunc(canaryGrace, func() {
			c.mu.Lock()
			if c.run == nil {
				c.active.Store(false)
			}
			c.mu.Unlock()
		})
	}()

	// Release the helper only after its pid is registered.
	_, _ = stdin.Write([]byte("go\n"))
	stdin.Close()
	_ = cmd.Wait()
	// The helper has exited: all its kernel events are in the rings.
	exited := time.Now()
	return c.await(run, sources, exited, timeout, maxBacklog, progress, stop), nil
}

// await waits for the helper's events and classifies the silent sources.
func (c *Canary) await(run *canaryRun, sources []string, exited time.Time, timeout, maxBacklog time.Duration,
	progress ProgressFunc, stop <-chan struct{}) CanaryResult {

	since := exited.Add(canarySettleMargin)
	deadline := exited.Add(timeout)
	giveUp := exited.Add(max(maxBacklog, timeout))
	type idleObs struct {
		token uint64
		at    time.Time
	}
	idle := map[string]idleObs{}
	for {
		var res CanaryResult
		c.mu.Lock()
		var silent []string
		for _, s := range sources {
			if !run.seen[s] {
				silent = append(silent, s)
			}
		}
		c.mu.Unlock()
		now := time.Now()
		if len(silent) == 0 {
			return res
		}
		if now.Before(deadline) {
			if !sleepOrStop(100*time.Millisecond, stop) {
				return CanaryResult{}
			}
			continue
		}
		for _, s := range silent {
			if progress == nil {
				res.Missing = append(res.Missing, s)
				continue
			}
			settled, definitive, token := progress(s, since)
			switch {
			case definitive:
				res.Missing = append(res.Missing, s)
			case settled:
				if o, ok := idle[s]; ok && o.token == token && now.Sub(o.at) >= canaryIdleConfirm {
					res.Missing = append(res.Missing, s)
				} else {
					if !ok || o.token != token {
						idle[s] = idleObs{token, now}
					}
					res.Lagging = append(res.Lagging, s)
				}
			default:
				delete(idle, s)
				res.Lagging = append(res.Lagging, s)
			}
		}
		if len(res.Lagging) == 0 || now.After(giveUp) {
			return res
		}
		if !sleepOrStop(100*time.Millisecond, stop) {
			return CanaryResult{}
		}
	}
}

// ActiveSources lists the event sources the listener is delivering and the
// canary can verify.
func (l *Listener) ActiveSources() []string {
	var s []string
	if l.enableExec {
		s = append(s, SourceProcessExec)
	}
	if l.enableFile {
		s = append(s, SourceFileCreate)
	}
	if l.enableNet {
		s = append(s, SourceNetConnect)
	}
	if l.enableAudit {
		s = append(s, SourceAudit)
	}
	return s
}

// RunCanaryChild is executed by the helper process; arg is os.Args[1].
func RunCanaryChild(arg string) error {
	nonce := os.Getenv(canaryNonceEnv)
	if !validNonce(nonce) {
		return errors.New("invalid canary nonce")
	}
	switch arg {
	case CanaryArg:
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "go" {
			return errors.New("canary not released")
		}
		// Re-exec: this exec event happens after Aurora registered our pid.
		return syscall.Exec("/proc/self/exe", []string{"aurora-canary", CanaryStage2Arg}, os.Environ())
	case CanaryStage2Arg:
		canaryActions(nonce)
		return nil
	}
	return errors.New("unknown canary stage")
}

func validNonce(s string) bool {
	if len(s) != 16 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// sleepOrStop sleeps for d; it returns false early if stop is closed.
func sleepOrStop(d time.Duration, stop <-chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
		return false
	case <-t.C:
		return true
	}
}
