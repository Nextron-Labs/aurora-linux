package ebpf

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
)

// watchKey mirrors struct watch_key in audit_monitor.c (LPM trie key).
type watchKey struct {
	PrefixLen uint32
	Data      [watchKeyBytes]byte
}

// hookCoverage lists, per security-hook program, the syscall tracepoint
// programs of audit_monitor.c it replaces. A tracepoint is only skipped when
// the hook covering it is attached, so kernels without fentry (or without
// CONFIG_SECURITY_PATH) keep the tracepoint fallback per operation.
var hookCoverage = map[string][]string{
	"hook_file_open":        {"audit_open", "audit_openat", "audit_openat2", "audit_creat"},
	"hook_path_mknod":       {"audit_mknod", "audit_mknodat"},
	"hook_path_mkdir":       {"audit_mkdir", "audit_mkdirat"},
	"hook_path_unlink":      {"audit_unlink", "audit_unlinkat"},
	"hook_path_rmdir":       {"audit_rmdir"},
	"hook_path_rename":      {"audit_rename", "audit_renameat", "audit_renameat2"},
	"hook_path_link":        {"audit_link", "audit_linkat"},
	"hook_path_symlink":     {"audit_symlink", "audit_symlinkat"},
	"hook_inode_setattr":    {"audit_chmod", "audit_fchmodat", "audit_fchmodat2", "audit_chown", "audit_lchown", "audit_fchownat", "audit_utimensat", "audit_truncate"},
	"hook_socket_connect":   {"audit_connect"},
	"hook_syslog":           {"audit_syslog"},
	"hook_kernel_load_data": {"audit_init_module"},
	"hook_kernel_read_file": {"audit_finit_module"},
	"hook_file_truncate":    nil,
	// syscall_hooks.c (per-ABI entry points, compat callers included)
	"sc_sysinfo64":     {"audit_sysinfo"},
	"sc_personality64": {"audit_personality"},
	"sc_memfd64":       {"audit_memfd_create"},
	"sc_delmod64":      {"audit_delete_module"},
}

// forceLegacyHooks selects the legacy (no bpf_loop) hook programs even on new
// kernels; AURORA_BPF_LEGACY=1, used to test the pre-5.17 code path.
func forceLegacyHooks() bool { return os.Getenv("AURORA_BPF_LEGACY") == "1" }

// loadHookCollection loads the modern variant of a hook object and falls back
// to the legacy one (kernels without bpf_loop, < 5.17).
func loadHookCollection(name string, modern, legacy func() (*ebpf.CollectionSpec, error),
	opts ebpf.CollectionOptions) (*ebpf.CollectionSpec, *ebpf.Collection, bool, error) {
	var firstErr error
	if !forceLegacyHooks() {
		spec, err := modern()
		if err == nil {
			coll, err2 := ebpf.NewCollectionWithOptions(spec, opts)
			if err2 == nil {
				return spec, coll, false, nil
			}
			err = err2
		}
		firstErr = err
		log.WithError(err).WithField("object", name).Debug("Modern hook programs unavailable; trying the legacy variant")
	}
	spec, err := legacy()
	if err != nil {
		return nil, nil, false, errors.Join(firstErr, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, nil, false, errors.Join(firstErr, classifyBPFError(err, name))
	}
	return spec, coll, true, nil
}

// initHooks loads audit_hooks.c and attaches every security hook available.
// It returns the set of tracepoint programs that no longer need to run.
func (l *Listener) initHooks() (map[string]bool, error) {
	spec, coll, legacy, err := loadHookCollection("audit_hooks", loadAuditHooks, loadAuditHooksLegacy, ebpf.CollectionOptions{})
	if err != nil {
		return nil, err
	}
	if err := l.registerSelfPID(coll.Maps["self_pids"], "audit-hooks"); err != nil {
		coll.Close()
		return nil, err
	}

	covered := map[string]bool{}
	var links []link.Link
	names := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		lnk, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[n], AttachType: ebpf.AttachTraceFEntry})
		if err != nil {
			log.WithError(err).WithField("hook", spec.Programs[n].AttachTo).Debug("Security hook unavailable; keeping tracepoint fallback")
			continue
		}
		links = append(links, lnk)
		for _, tp := range hookCoverage[n] {
			covered[tp] = true
		}
	}
	closeAll := func() {
		for _, lnk := range links {
			lnk.Close()
		}
		coll.Close()
	}
	if len(links) == 0 {
		closeAll()
		return nil, errors.New("no security hook could be attached (kernel without BTF/fentry?)")
	}

	rd, err := ringbuf.NewReader(coll.Maps["hook_events"])
	if err != nil {
		closeAll()
		return nil, err
	}

	// Per-ABI syscall entry hooks for the syscalls without an LSM hook. They
	// share this object's ring buffer and self-exclusion map.
	if scSpec, err := loadSyscallHooks(); err == nil {
		scColl, err := ebpf.NewCollectionWithOptions(scSpec, ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"hook_events":      coll.Maps["hook_events"],
				"hook_lost_events": coll.Maps["hook_lost_events"],
				"self_pids":        coll.Maps["self_pids"],
			},
		})
		if err != nil {
			log.WithError(err).Debug("Syscall entry hooks unavailable; keeping tracepoints")
		} else {
			l.scColl = scColl
			scNames := make([]string, 0, len(scSpec.Programs))
			for n := range scSpec.Programs {
				scNames = append(scNames, n)
			}
			sort.Strings(scNames)
			for _, n := range scNames {
				lnk, err := link.AttachTracing(link.TracingOptions{Program: scColl.Programs[n], AttachType: ebpf.AttachTraceFEntry})
				if err != nil {
					log.WithError(err).WithField("hook", scSpec.Programs[n].AttachTo).Debug("Syscall entry hook unavailable")
					continue
				}
				links = append(links, lnk)
				for _, tp := range hookCoverage[n] {
					covered[tp] = true
				}
			}
		}
	}

	l.registry = newWatchRegistry(l.auditWatch, coll.Maps["watch_inodes"], coll.Maps["watch_names"])
	l.registry.sync()
	l.hookColl, l.hookLinks, l.hookRd = coll, links, rd
	l.registryStop = make(chan struct{})
	l.wgRegistry.Add(1)
	go l.registryLoop()

	log.WithFields(log.Fields{"hooks": len(links), "legacy": legacy}).Info("Security-hook file/network monitor attached")
	return covered, nil
}

// registryLoop keeps the inode watches current: periodically (new users,
// package updates) and right after watched objects are created.
func (l *Listener) registryLoop() {
	defer l.wgRegistry.Done()
	t := time.NewTicker(registryRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-l.registryStop:
			return
		case <-t.C:
		case <-l.registry.refresh:
			// Coalesce bursts (e.g. package installs).
			time.Sleep(200 * time.Millisecond)
		}
		l.registry.sync()
	}
}

// initAudit loads the security-hook monitor (preferred) and audit_monitor.c
// for everything the hooks do not cover, populates the in-kernel filters and
// attaches every syscall tracepoint that exists on this kernel/architecture.
func (l *Listener) initAudit() error {
	l.auditWatch = newWatchSet(defaultAuditWatches)
	covered, herr := l.initHooks()
	if herr != nil {
		log.WithError(herr).Warn("Security-hook monitor unavailable; using syscall tracepoints (path matching can be evaded on this kernel)")
	}
	// The canary's sysinfo record comes from whichever side attached it.
	l.sysinfoViaHook = covered["audit_sysinfo"]
	err := l.initAuditTracepoints(covered)
	if err != nil && l.hookColl != nil {
		// The hooks work on their own; only the records they do not cover
		// (see hookCoverage) are missing. Failing here would leave the
		// attached hooks writing into a ring nobody reads.
		log.WithError(err).Warn("Audit tracepoint monitor unavailable; auditd-compatible records limited to the security hooks")
		return nil
	}
	return err
}

// initAuditTracepoints loads audit_monitor.c for the records the hooks do
// not cover.
func (l *Listener) initAuditTracepoints(covered map[string]bool) error {
	spec, err := loadAuditMonitor()
	if err != nil {
		return classifyBPFError(err, "audit_monitor")
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return classifyBPFError(err, "audit_monitor")
	}

	fail := func(err error) error {
		for _, lnk := range l.auditLinks {
			lnk.Close()
		}
		l.auditLinks = nil
		coll.Close()
		return err
	}

	if err := l.registerSelfPID(coll.Maps["self_pids"], "audit"); err != nil {
		return fail(err)
	}

	if err := populateWatchPrefixes(coll.Maps["watch_prefixes"], l.auditWatch); err != nil {
		return fail(err)
	}

	// Deterministic attach order for reproducible logs.
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)

	attached := 0
	for _, name := range names {
		if covered[name] {
			continue
		}
		group, event, ok := tracepointFromSection(spec.Programs[name].SectionName)
		if !ok {
			continue
		}
		lnk, err := link.Tracepoint(group, event, coll.Programs[name], nil)
		if err != nil {
			// Not every syscall exists on every architecture/kernel
			// (e.g. open/mkdir/rename on arm64, fchmodat2 before 6.6).
			log.WithError(err).WithField("tracepoint", group+"/"+event).Debug("Audit tracepoint unavailable; skipping")
			continue
		}
		l.auditLinks = append(l.auditLinks, lnk)
		attached++
	}
	if attached == 0 && l.hookColl == nil {
		return fail(errors.New("no syscall tracepoint could be attached"))
	}

	rd, err := ringbuf.NewReader(coll.Maps["audit_events"])
	if err != nil {
		return fail(fmt.Errorf("creating audit ring buffer reader: %w", err))
	}

	l.auditColl = coll
	l.auditRd = rd
	log.WithField("tracepoints", attached).Info("Audit-compatible eBPF monitor attached")
	return nil
}

// tracepointFromSection splits "tracepoint/<group>/<event>".
func tracepointFromSection(section string) (group, event string, ok bool) {
	parts := strings.Split(section, "/")
	if len(parts) != 3 || parts[0] != "tracepoint" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// populateWatchPrefixes fills the LPM trie used as in-kernel path pre-filter.
func populateWatchPrefixes(m *ebpf.Map, ws *watchSet) error {
	if m == nil {
		return errors.New("watch_prefixes map missing")
	}
	for prefix, needsHidden := range ws.kernelPrefixes() {
		key := watchKey{PrefixLen: uint32(len(prefix)) * 8}
		copy(key.Data[:], prefix)
		var val uint8
		if needsHidden {
			val = 1
		}
		if err := m.Put(key, val); err != nil {
			return fmt.Errorf("adding watch prefix %q: %w", prefix, err)
		}
	}
	return nil
}

// readAuditEvents drains the audit ring buffer.
func (l *Listener) readAuditEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	var record ringbuf.Record
	pg := l.progress(progAudit)
	for {
		pg.beginRead()
		err := l.auditRd.ReadInto(&record)
		pg.endRead()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading audit ring buffer")
			if l.closed.Load() {
				return
			}
			time.Sleep(readErrorBackoff)
			continue
		}

		events, err := l.parseAuditEvents(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing audit event")
			continue
		}
		var ts time.Time
		for _, e := range events {
			callback(e)
			ts = e.Time()
		}
		pg.processed(ts)
	}
}

// readHookEvents drains the security-hook ring buffer.
func (l *Listener) readHookEvents(callback func(event provider.Event)) {
	defer l.wg.Done()
	var record ringbuf.Record
	pg := l.progress(progHook)
	for {
		pg.beginRead()
		err := l.hookRd.ReadInto(&record)
		pg.endRead()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			if l.closed.Load() {
				return
			}
			time.Sleep(readErrorBackoff)
			continue
		}
		var raw bpfHookEvent
		if err := decodeHookEvent(record.RawSample, &raw); err != nil {
			continue
		}
		proc := &auditProc{
			pid: raw.Pid, ppid: raw.Ppid, uid: raw.Uid, gid: raw.Gid, euid: raw.Euid, egid: raw.Egid,
			comm: nullTermStr(raw.Comm[:], len(raw.Comm)),
			ts:   l.ktimeToWall(raw.TimestampNs),
		}
		proc.exe, proc.auid = l.idents.resolve(raw.Pid, raw.StartNs, raw.ExecID)
		if proc.exe == "" {
			// Exited before /proc was read and its exec event not handled
			// yet: the kernel's record of that exec (same generation).
			proc.exe = l.peekKernelExePath(raw.Pid, raw.ExecID)
		}
		if raw.Op == hookOpMkdir || raw.Op == hookOpRename || raw.Op == hookOpSymlink {
			// A new directory may lie on the way to a watched location.
			l.registry.requestRefresh()
		}
		for _, e := range auditRecordsForHook(&raw, proc, l.auditWatch, l.registry, func(string) { l.registry.requestRefresh() }) {
			callback(e)
		}
		pg.processed(proc.ts)
	}
}

// parseAuditEvents converts one audit_monitor sample into auditd-shaped records.
func (l *Listener) parseAuditEvents(data []byte) ([]provider.Event, error) {
	var raw bpfAuditEvent
	if err := decodeAuditEvent(data, &raw); err != nil {
		return nil, err
	}

	proc := &auditProc{
		pid:  raw.Pid,
		ppid: raw.Ppid,
		uid:  raw.Uid,
		gid:  raw.Gid,
		euid: raw.Euid,
		egid: raw.Egid,
		comm: nullTermStr(raw.Comm[:], len(raw.Comm)),
		ts:   l.ktimeToWall(raw.TimestampNs),
	}
	proc.exe, proc.auid = l.idents.resolve(raw.Pid, raw.StartNs, 0)

	watches := l.auditWatch
	if watches == nil {
		watches = newWatchSet(defaultAuditWatches)
	}
	return auditRecordsForSyscall(&raw, proc, watches, fileBirthTime), nil
}

// auditEventsForExec derives the auditd records of an execve from the details
// collected for the process_creation event.
func (l *Listener) auditEventsForExec(d *execDetails, ts time.Time) []provider.Event {
	proc := &auditProc{
		pid:  d.raw.Pid,
		ppid: d.raw.Ppid,
		uid:  d.raw.Uid,
		gid:  d.raw.Gid,
		euid: d.raw.Euid,
		egid: d.raw.Egid,
		comm: nullTermStr(d.raw.Comm[:], len(d.raw.Comm)),
		exe:  d.image,
		auid: auditLoginUIDValue(d.loginUID),
		cwd:  d.cwd,
		ts:   ts,
	}
	l.idents.put(proc.pid, procIdentity{startNs: d.raw.StartNs, execID: d.raw.ExecID, exe: proc.exe, auid: proc.auid})
	return auditRecordsForExec(proc, d.filename, d.argv)
}

func auditLoginUID(pid uint32) string { return auditLoginUIDValue(readLoginUID(pid)) }

func auditLoginUIDValue(v string) string {
	if v == "" {
		return auditUnsetID
	}
	return v
}
