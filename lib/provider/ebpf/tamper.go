package ebpf

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Severity of a tamper alert.
const (
	SeverityInfo     = "info"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// TamperAlert reports an attempt to stop, blind or reconfigure Aurora.
type TamperAlert struct {
	Time     time.Time
	Kind     string // e.g. "signal", "ptrace", "bpf-management", "blind-source"
	Severity string
	Message  string
	Fields   map[string]string
}

// Event kinds, identical to enum tamper_kind in tamper_hooks.c /
// tamper_monitor.c.
const (
	tkSignal uint32 = iota + 1
	tkPtrace
	tkVMWrite
	tkVMRead
	tkBPFMgmt
	tkBPFLoad
	tkPidfdGetfd
	tkBPFAttach
	tkSigio
	tkSched
	tkControlWrite
)

// LSM kinds (enum lsm_kind in tamper_lsm.c) mapped to the kinds above.
var lsmKinds = map[uint32]uint32{1: tkSignal, 2: tkPtrace, 3: tkBPFMgmt, 4: tkSigio, 5: tkSched, 6: tkControlWrite}

const tamperPathBytes = 256

// bpfTamperEvent mirrors struct tamper_event (tamper_hooks.c; the tracepoint
// and LSM variants have no path).
type bpfTamperEvent struct {
	TimestampNs uint64
	Kind        uint32
	Pid         uint32
	Uid         uint32
	Target      uint32
	Arg         uint32
	Arg2        uint32
	Comm        [16]byte
	Path        [tamperPathBytes]byte
}

// bpfLastFatal mirrors struct last_fatal in tamper_hooks.c.
type bpfLastFatal struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Sig         uint32
	Target      uint32
	Comm        [16]byte
}

// FatalRecord describes the last fatal signal sent to a previous Aurora
// instance (persisted in a pinned BPF map, so it survives SIGKILL).
type FatalRecord struct {
	ActorPid  uint32
	ActorUID  uint32
	ActorComm string
	Signal    string
	Target    uint32
	Time      time.Time
}

// Pin directory for state that must survive Aurora being killed.
const tamperPinDir = "/sys/fs/bpf/aurora"

// TamperSensor watches for attempts to kill, debug or reconfigure Aurora
// (detection) and, optionally, denies them through BPF-LSM (enforcement).
type TamperSensor struct {
	pid       uint32
	bootNanos int64

	mon      *ebpf.Collection
	monLinks []link.Link
	monRd    *ringbuf.Reader
	hooks    bool // security-hook detection (vs. tracepoint fallback)

	lsm      *ebpf.Collection
	lsmLinks []link.Link
	lsmRd    *ringbuf.Reader

	enforceErr error
	prevFatal  *FatalRecord
	wg         sync.WaitGroup

	dedupMu sync.Mutex
	dedup   map[string]*dedupState

	// limiter caps the rate of non-critical alerts; critical ones are never
	// dropped. Dropped alerts are counted and reported with the next alert.
	limiter *rate.Limiter
	dropped atomic.Uint64
}

// dedupState coalesces bursts: one bpftool invocation issues hundreds of
// identical bpf(2) calls.
type dedupState struct {
	last       time.Time
	suppressed int
}

const (
	dedupWindow = 10 * time.Second
	// dedupMaxKeys bounds the map. Keys are (kind, actor), and the hooks
	// only fire after the kernel's own permission checks, so unprivileged
	// users cannot mint keys.
	dedupMaxKeys = 4096
)

// admit reports whether an alert with this key should be emitted now and how
// many identical ones were folded into it since the last emission.
func (s *TamperSensor) admit(key string, now time.Time) (bool, int) {
	s.dedupMu.Lock()
	defer s.dedupMu.Unlock()
	if s.dedup == nil {
		s.dedup = map[string]*dedupState{}
	}
	st, ok := s.dedup[key]
	if !ok {
		if len(s.dedup) >= dedupMaxKeys {
			for k, v := range s.dedup { // drop expired entries
				if now.Sub(v.last) >= dedupWindow {
					delete(s.dedup, k)
				}
			}
			if len(s.dedup) >= dedupMaxKeys {
				return false, 0 // still full of fresh keys: shed load
			}
		}
		s.dedup[key] = &dedupState{last: now}
		return true, 0
	}
	if now.Sub(st.last) < dedupWindow {
		st.suppressed++
		return false, 0
	}
	n := st.suppressed
	st.last, st.suppressed = now, 0
	return true, n
}

// NewTamperSensor loads the detection programs for the protected (host) pid
// and, if enforce is set, the BPF-LSM enforcement programs. If enforcement
// cannot be enabled the sensor still works in detection mode;
// EnforceError() tells why.
func NewTamperSensor(pid uint32, enforce bool) (*TamperSensor, error) {
	s := &TamperSensor{pid: pid, bootNanos: bootTimeNanos(), limiter: rate.NewLimiter(rate.Limit(20), 100)}
	if err := s.initHooks(); err != nil {
		log.WithError(err).Warn("Tamper security hooks unavailable; using syscall tracepoints (thread-id and process-group kills are not detected)")
		if err := s.initTracepoints(); err != nil {
			s.Close()
			return nil, err
		}
	}
	if enforce {
		if err := s.initLSM(); err != nil {
			s.enforceErr = err
		}
	}
	return s, nil
}

// Enforcing reports whether the BPF-LSM deny hooks are active.
func (s *TamperSensor) Enforcing() bool { return s.lsm != nil }

// EnforceError is why enforcement could not be enabled (nil if it is, or was
// not requested).
func (s *TamperSensor) EnforceError() error { return s.enforceErr }

// PreviousFatal returns the fatal signal recorded for a previous instance,
// if any (consumed at start-up).
func (s *TamperSensor) PreviousFatal() *FatalRecord { return s.prevFatal }

func (s *TamperSensor) initHooks() error {
	opts := ebpf.CollectionOptions{}
	pin := pinDirUsable()
	if pin {
		opts.Maps.PinPath = tamperPinDir
	}
	unpinned := func(load func() (*ebpf.CollectionSpec, error)) func() (*ebpf.CollectionSpec, error) {
		return func() (*ebpf.CollectionSpec, error) {
			spec, err := load()
			if err == nil && !pin {
				if ms := spec.Maps["aurora_last_fatal"]; ms != nil {
					ms.Pinning = ebpf.PinNone
				}
			}
			return spec, err
		}
	}
	spec, coll, _, err := loadHookCollection("tamper_hooks", unpinned(loadTamperHooks), unpinned(loadTamperHooksLegacy), opts)
	if err != nil {
		return err
	}
	s.mon = coll
	if err := coll.Maps["protected_pids"].Put(s.pid, uint8(1)); err != nil {
		return fmt.Errorf("registering protected pid: %w", err)
	}
	s.consumeLastFatal(coll.Maps["aurora_last_fatal"])

	names := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		lnk, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[n], AttachType: ebpf.AttachTraceFEntry})
		if err != nil {
			log.WithError(err).WithField("hook", spec.Programs[n].AttachTo).Debug("Tamper hook unavailable")
			continue
		}
		s.monLinks = append(s.monLinks, lnk)
	}
	if len(s.monLinks) == 0 {
		s.closeMonitor()
		return errors.New("no tamper security hook could be attached")
	}
	if s.monRd, err = ringbuf.NewReader(coll.Maps["tamper_events"]); err != nil {
		s.closeMonitor()
		return err
	}
	s.hooks = true
	return nil
}

// pinDirUsable prepares the bpffs pin directory; false if bpffs is absent.
func pinDirUsable() bool {
	var st syscallStatfs
	if !statfsIsBPF("/sys/fs/bpf", &st) {
		return false
	}
	return os.MkdirAll(tamperPinDir, 0o700) == nil
}

// consumeLastFatal reads and clears the record left by a previous instance.
func (s *TamperSensor) consumeLastFatal(m *ebpf.Map) {
	if m == nil {
		return
	}
	var lf bpfLastFatal
	if err := m.Lookup(uint32(0), &lf); err != nil || lf.Pid == 0 {
		return
	}
	s.prevFatal = &FatalRecord{
		ActorPid:  lf.Pid,
		ActorUID:  lf.Uid,
		ActorComm: cleanText(nullTermStr(lf.Comm[:], len(lf.Comm))),
		Signal:    signalName(lf.Sig),
		Target:    lf.Target,
		Time:      s.ktime(lf.TimestampNs),
	}
	_ = m.Put(uint32(0), bpfLastFatal{})
}

func (s *TamperSensor) initTracepoints() error {
	spec, err := loadTamperMonitor()
	if err != nil {
		return classifyBPFError(err, "tamper_monitor")
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return classifyBPFError(err, "tamper_monitor")
	}
	s.mon = coll
	if err := coll.Maps["protected_pids"].Put(s.pid, uint8(1)); err != nil {
		return fmt.Errorf("registering protected pid: %w", err)
	}
	s.monLinks, err = attachTracepoints(spec, coll)
	if err != nil {
		return err
	}
	s.monRd, err = ringbuf.NewReader(coll.Maps["tamper_events"])
	return err
}

func (s *TamperSensor) initLSM() error {
	if !bpfLSMActive() {
		return errors.New("BPF-LSM is not active: boot with lsm=...,bpf (CONFIG_BPF_LSM required)")
	}
	spec, err := loadTamperLsm()
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("loading LSM programs: %w", err)
	}
	if err := coll.Maps["lsm_protected"].Put(s.pid, uint8(1)); err != nil {
		coll.Close()
		return err
	}
	var links []link.Link
	for name := range spec.Programs {
		lnk, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs[name]})
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			coll.Close()
			return fmt.Errorf("attaching LSM program %s: %w", name, err)
		}
		links = append(links, lnk)
	}
	rd, err := ringbuf.NewReader(coll.Maps["lsm_events"])
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
		return err
	}
	s.lsm, s.lsmLinks, s.lsmRd = coll, links, rd
	return nil
}

// bpfLSMActive reports whether "bpf" is in the active LSM list.
func bpfLSMActive() bool {
	raw, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return true // securityfs not visible (container?): try, attach will fail if absent
	}
	for _, m := range strings.Split(strings.TrimSpace(string(raw)), ",") {
		if m == "bpf" {
			return true
		}
	}
	return false
}

// attachTracepoints attaches every "tracepoint/<group>/<event>" program.
func attachTracepoints(spec *ebpf.CollectionSpec, coll *ebpf.Collection) ([]link.Link, error) {
	names := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	var links []link.Link
	for _, n := range names {
		group, event, ok := tracepointFromSection(spec.Programs[n].SectionName)
		if !ok {
			continue
		}
		lnk, err := link.Tracepoint(group, event, coll.Programs[n], nil)
		if err != nil {
			log.WithError(err).WithField("tracepoint", group+"/"+event).Debug("Tamper tracepoint unavailable; skipping")
			continue
		}
		links = append(links, lnk)
	}
	if len(links) == 0 {
		return nil, errors.New("no tamper tracepoint could be attached")
	}
	return links, nil
}

// OwnObjects returns the IDs of the programs, maps and links the sensor
// created (so they can be protected like the listener's).
func (s *TamperSensor) OwnObjects() BPFObjectIDs {
	var ids BPFObjectIDs
	for _, c := range []*ebpf.Collection{s.mon, s.lsm} {
		ids.addCollection(c)
	}
	ids.addLinks(s.monLinks...)
	ids.addLinks(s.lsmLinks...)
	return ids
}

// ProtectObjects registers Aurora's BPF objects: any other process obtaining
// an fd to them is reported (and denied in enforce mode).
func (s *TamperSensor) ProtectObjects(ids BPFObjectIDs) {
	put := func(c *ebpf.Collection, name string, vals []uint32) {
		if c == nil || c.Maps[name] == nil {
			return
		}
		for _, v := range vals {
			_ = c.Maps[name].Put(v, uint8(1))
		}
	}
	put(s.mon, "aurora_prog_ids", ids.Programs)
	put(s.mon, "aurora_map_ids", ids.Maps)
	put(s.mon, "aurora_link_ids", ids.Links)
	put(s.lsm, "lsm_prog_ids", ids.Programs)
	put(s.lsm, "lsm_map_ids", ids.Maps)
	put(s.lsm, "lsm_link_ids", ids.Links)
}

// ProtectInodes registers control files (Aurora's cgroup files,
// /proc/<aurora>/oom_score_adj) whose modification by others is reported
// (and denied in enforce mode).
func (s *TamperSensor) ProtectInodes(keys []hookInodeKey) {
	for _, k := range keys {
		if s.mon != nil && s.mon.Maps["protected_inodes"] != nil {
			_ = s.mon.Maps["protected_inodes"].Put(k, uint8(1))
		}
		if s.lsm != nil && s.lsm.Maps["lsm_protected_inodes"] != nil {
			_ = s.lsm.Maps["lsm_protected_inodes"].Put(k, uint8(1))
		}
	}
}

// Lost returns the number of tamper events dropped because the ring was full.
func (s *TamperSensor) Lost() uint64 {
	if s.mon == nil {
		return 0
	}
	return readLostCounter(s.mon.Maps["tamper_lost"])
}

// Run delivers alerts until Close is called. It blocks.
func (s *TamperSensor) Run(alert func(TamperAlert)) {
	if s.monRd != nil {
		s.wg.Add(1)
		go s.read(s.monRd, false, alert)
	}
	if s.lsmRd != nil {
		s.wg.Add(1)
		go s.read(s.lsmRd, true, alert)
	}
	s.wg.Wait()
}

func (s *TamperSensor) read(rd *ringbuf.Reader, blocked bool, alert func(TamperAlert)) {
	defer s.wg.Done()
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(readErrorBackoff)
			continue
		}
		var raw bpfTamperEvent
		if err := decodeTamperEvent(rec.RawSample, &raw); err != nil {
			continue
		}
		if blocked {
			raw.Kind = lsmKinds[raw.Kind]
		}
		a := s.buildAlert(&raw, blocked)
		// Dedup per (kind, actor): argument variations by the same actor
		// (signal numbers, bpf commands) cannot defeat it.
		key := fmt.Sprintf("%s|%d|%t", a.Kind, raw.Pid, blocked)
		ok, folded := s.admit(key, time.Now())
		if !ok {
			continue
		}
		if a.Severity != SeverityCritical && s.limiter != nil && !s.limiter.Allow() {
			s.dropped.Add(1)
			continue
		}
		if folded > 0 {
			a.Fields["repeated_events_folded"] = strconv.Itoa(folded)
		}
		if d := s.dropped.Swap(0); d > 0 {
			a.Fields["alerts_dropped_by_rate_limit"] = strconv.FormatUint(d, 10)
		}
		alert(a)
	}
}

var signalNames = map[uint32]string{
	1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS",
	8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE",
	14: "SIGALRM", 15: "SIGTERM", 17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
	21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ", 26: "SIGVTALRM",
	27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO", 30: "SIGPWR", 31: "SIGSYS",
}

func signalName(n uint32) string {
	if s, ok := signalNames[n]; ok {
		return s
	}
	return "signal " + strconv.FormatUint(uint64(n), 10)
}

// harmlessSignal: signals that cannot stop or kill Aurora.
func harmlessSignal(n uint32) bool {
	switch n {
	case 17, 18, 23, 28: // SIGCHLD, SIGCONT, SIGURG, SIGWINCH
		return true
	}
	return false
}

var bpfCmdLabel = map[uint32]string{
	5: "BPF_PROG_LOAD", 7: "BPF_OBJ_GET", 9: "BPF_PROG_DETACH", 13: "BPF_PROG_GET_FD_BY_ID",
	14: "BPF_MAP_GET_FD_BY_ID", 17: "BPF_RAW_TRACEPOINT_OPEN", 28: "BPF_LINK_CREATE",
	29: "BPF_LINK_UPDATE", 30: "BPF_LINK_GET_FD_BY_ID", 34: "BPF_LINK_DETACH",
}

func bpfCmdName2(cmd uint32) string {
	if n, ok := bpfCmdLabel[cmd]; ok {
		return n
	}
	return bpfCmdName(cmd)
}

// cleanText replaces control characters in attacker-influenced strings
// (comm names can contain newlines and escape sequences).
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// buildAlert turns a kernel event into an alert. In the monitor stream the
// action is being attempted (it passed the kernel's own permission checks);
// in the LSM stream it was denied.
func (s *TamperSensor) buildAlert(e *bpfTamperEvent, blocked bool) TamperAlert {
	comm := cleanText(nullTermStr(e.Comm[:], len(e.Comm)))
	f := map[string]string{
		"actor_pid":  strconv.FormatUint(uint64(e.Pid), 10),
		"actor_comm": comm,
		"actor_uid":  strconv.FormatUint(uint64(e.Uid), 10),
		"aurora_pid": strconv.FormatUint(uint64(s.pid), 10),
		"blocked":    strconv.FormatBool(blocked),
	}
	// Best effort: the actor may already have exited or rewritten its argv.
	if exe, err := readExeLink(e.Pid); err == nil {
		f["actor_exe"] = cleanText(exe)
	}
	if cmd, err := readCmdline(e.Pid); err == nil {
		c, _ := joinCmdline(cmd)
		f["actor_cmdline"] = cleanText(c)
	}

	verb := "attempted"
	if blocked {
		verb = "was blocked from attempting"
	}
	a := TamperAlert{Time: s.ktime(e.TimestampNs), Fields: f, Severity: SeverityHigh}
	switch e.Kind {
	case tkSignal:
		a.Kind = "signal"
		f["signal"] = signalName(e.Arg)
		switch {
		case e.Pid == 1 && e.Arg == 15:
			a.Severity = SeverityMedium
			a.Message = "Aurora is being stopped by the service manager (SIGTERM from pid 1)"
		case harmlessSignal(e.Arg):
			a.Severity = SeverityMedium
			a.Message = fmt.Sprintf("%s (pid %d) %s to send %s to Aurora", comm, e.Pid, verb, signalName(e.Arg))
		default:
			// Any other signal stops or terminates Aurora.
			a.Severity = SeverityCritical
			a.Message = fmt.Sprintf("%s (pid %d) %s to send %s to Aurora", comm, e.Pid, verb, signalName(e.Arg))
		}
	case tkSigio:
		a.Kind = "signal"
		f["signal"] = signalName(e.Arg)
		a.Severity = SeverityCritical
		a.Message = fmt.Sprintf("%s (pid %d) %s to deliver %s to Aurora through F_SETOWN/F_SETSIG", comm, e.Pid, verb, signalName(e.Arg))
	case tkPtrace:
		a.Kind = "ptrace"
		a.Severity = SeverityCritical
		a.Message = fmt.Sprintf("%s (pid %d) %s to ptrace or access Aurora's memory", comm, e.Pid, verb)
	case tkVMWrite:
		a.Kind = "process-memory-write"
		a.Severity = SeverityCritical
		a.Message = fmt.Sprintf("%s (pid %d) %s to write Aurora's memory (process_vm_writev)", comm, e.Pid, verb)
	case tkVMRead:
		a.Kind = "process-memory-read"
		a.Message = fmt.Sprintf("%s (pid %d) %s to read Aurora's memory (process_vm_readv)", comm, e.Pid, verb)
	case tkSched:
		a.Kind = "scheduling"
		what := map[uint32]string{1: "nice value", 2: "scheduling policy", 3: "I/O priority"}[e.Arg]
		f["changed"] = what
		a.Message = fmt.Sprintf("%s (pid %d) %s to change Aurora's %s (starvation)", comm, e.Pid, verb, what)
	case tkControlWrite:
		a.Kind = "control-file-write"
		a.Severity = SeverityCritical
		p := cleanText(nullTermStr(e.Path[:], len(e.Path)))
		if p != "" {
			f["path"] = p
		}
		a.Message = fmt.Sprintf("%s (pid %d) %s to write Aurora's control file %s (kill/freeze/limit)", comm, e.Pid, verb, p)
	case tkBPFMgmt:
		a.Kind = "bpf-management"
		f["bpf_cmd"] = bpfCmdName2(e.Arg)
		if e.Arg == 5 || e.Arg == 17 || e.Arg == 28 { // denied load/attach (LSM stream)
			a.Kind = "bpf-program-load"
			f["bpf_prog_type"] = bpfProgTypeName(e.Arg2)
			a.Message = fmt.Sprintf("%s (pid %d) %s %s of a tracing-class eBPF program that can observe or interfere with Aurora", comm, e.Pid, verb, bpfCmdName2(e.Arg))
			break
		}
		if e.Arg2 != 0 {
			f["bpf_object_id"] = strconv.FormatUint(uint64(e.Arg2), 10)
		}
		a.Severity = SeverityCritical
		a.Message = fmt.Sprintf("%s (pid %d) %s %s on one of Aurora's eBPF objects: it can detach, replace or alter monitoring", comm, e.Pid, verb, bpfCmdName2(e.Arg))
	case tkBPFLoad:
		a.Kind = "bpf-program-load"
		f["bpf_cmd"] = "BPF_PROG_LOAD"
		f["bpf_prog_type"] = bpfProgTypeName(e.Arg2)
		a.Message = fmt.Sprintf("%s (pid %d) %s to load a %s eBPF program that can observe or interfere with Aurora", comm, e.Pid, verb, bpfProgTypeName(e.Arg2))
	case tkBPFAttach:
		a.Kind = "bpf-program-attach"
		f["bpf_cmd"] = bpfCmdName2(e.Arg)
		a.Message = fmt.Sprintf("%s (pid %d) %s to attach a tracing eBPF program (%s)", comm, e.Pid, verb, bpfCmdName2(e.Arg))
	case tkPidfdGetfd:
		a.Kind = "fd-theft"
		a.Severity = SeverityMedium
		a.Message = fmt.Sprintf("%s (pid %d) used pidfd_getfd(): it can copy and close another process's descriptors, e.g. Aurora's eBPF links", comm, e.Pid)
	default:
		a.Kind = "unknown"
		a.Message = "unknown tamper event"
	}
	return a
}

func (s *TamperSensor) ktime(ns uint64) time.Time {
	return time.Unix(0, s.bootNanos+int64(ns))
}

func (s *TamperSensor) closeMonitor() {
	for _, l := range s.monLinks {
		l.Close()
	}
	s.monLinks = nil
	if s.monRd != nil {
		s.monRd.Close()
		s.monRd = nil
	}
	if s.mon != nil {
		s.mon.Close()
		s.mon = nil
	}
}

// Close detaches and unloads everything.
func (s *TamperSensor) Close() {
	if s.monRd != nil {
		s.monRd.Close()
	}
	if s.lsmRd != nil {
		s.lsmRd.Close()
	}
	s.wg.Wait()
	s.monRd = nil
	s.closeMonitor()
	for _, l := range s.lsmLinks {
		l.Close()
	}
	s.lsmLinks = nil
	if s.lsm != nil {
		s.lsm.Close()
	}
	s.lsm, s.lsmRd = nil, nil
}
