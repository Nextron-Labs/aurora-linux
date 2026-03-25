package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

// Source strings recognized by AddSource.
const (
	SourceProcessExec = "LinuxEBPF:ProcessExec"
	SourceFileCreate  = "LinuxEBPF:FileCreate"
	SourceNetConnect  = "LinuxEBPF:NetConnect"
	SourceBpfEvent    = "LinuxEBPF:BpfEvent"

	readErrorBackoff = 100 * time.Millisecond
)

// Listener implements the EventProvider interface using eBPF tracepoints.
type Listener struct {
	// Which sources are enabled
	enableExec bool
	enableFile bool
	enableNet  bool
	enableBpf  bool

	// eBPF objects and links
	execObjs  *execMonitorObjects
	fileObjs  *fileMonitorObjects
	netObjs   *netMonitorObjects
	bpfObjs   *bpfMonitorObjects
	execLink  link.Link
	fileEnter link.Link
	fileExit  link.Link
	netLink   link.Link
	bpfEnter  link.Link
	bpfExit   link.Link

	// Ring buffer readers
	execReader *ringbuf.Reader
	fileReader *ringbuf.Reader
	netReader  *ringbuf.Reader
	bpfReader  *ringbuf.Reader

	// Correlation and caches
	correlator *enrichment.Correlator
	userCache  *UserCache

	// Bookkeeping
	closed    atomic.Bool
	wg        sync.WaitGroup
	bootNanos int64 // boot time in nanoseconds (for ktime -> wall clock)
	selfPID   uint32

	// Optional init hooks for tests.
	initExecFn func() error
	initFileFn func() error
	initNetFn  func() error
	initBpfFn  func() error
}

// NewListener creates a new eBPF listener with the given correlator.
func NewListener(correlator *enrichment.Correlator) *Listener {
	return &Listener{
		correlator: correlator,
	}
}

func (l *Listener) Name() string        { return ProviderName }
func (l *Listener) Description() string { return "eBPF-based telemetry provider for Linux" }

// AddSource enables a specific telemetry source.
func (l *Listener) AddSource(source string) error {
	switch source {
	case SourceProcessExec:
		l.enableExec = true
	case SourceFileCreate:
		l.enableFile = true
	case SourceNetConnect:
		l.enableNet = true
	case SourceBpfEvent:
		l.enableBpf = true
	default:
		return fmt.Errorf("unknown source: %s", source)
	}
	return nil
}

// Initialize loads BPF programs and attaches to tracepoints.
func (l *Listener) Initialize() error {
	// Compute boot time for ktime_get_ns → wall clock conversion
	l.bootNanos = bootTimeNanos()
	selfPID := os.Getpid()
	if selfPID <= 0 {
		return fmt.Errorf("invalid process id: %d", selfPID)
	}
	l.selfPID = uint32(selfPID)

	// Initialize user cache
	uc, err := NewUserCache(256)
	if err != nil {
		return fmt.Errorf("creating user cache: %w", err)
	}
	l.userCache = uc

	// Load and attach enabled BPF programs. A failing source is disabled,
	// while other sources are still attempted.
	requested := 0
	initialized := 0
	var initErrs []error

	if l.enableExec {
		requested++
		if err := l.initExecSource(); err != nil {
			l.enableExec = false
			initErrs = append(initErrs, fmt.Errorf("exec monitor: %w", err))
			log.WithError(err).Warn("Failed to initialize exec monitor; source disabled")
		} else {
			initialized++
		}
	}
	if l.enableFile {
		requested++
		if err := l.initFileSource(); err != nil {
			l.enableFile = false
			initErrs = append(initErrs, fmt.Errorf("file monitor: %w", err))
			log.WithError(err).Warn("Failed to initialize file monitor; source disabled")
		} else {
			initialized++
		}
	}
	if l.enableNet {
		requested++
		if err := l.initNetSource(); err != nil {
			l.enableNet = false
			initErrs = append(initErrs, fmt.Errorf("net monitor: %w", err))
			log.WithError(err).Warn("Failed to initialize net monitor; source disabled")
		} else {
			initialized++
		}
	}
	if l.enableBpf {
		requested++
		if err := l.initBpfSource(); err != nil {
			l.enableBpf = false
			initErrs = append(initErrs, fmt.Errorf("bpf monitor: %w", err))
			log.WithError(err).Warn("Failed to initialize bpf monitor; source disabled")
		} else {
			initialized++
		}
	}

	if requested > 0 && initialized == 0 {
		return fmt.Errorf("failed to initialize any eBPF monitor: %w", errors.Join(initErrs...))
	}

	if requested > initialized {
		log.WithFields(log.Fields{
			"requested":   requested,
			"initialized": initialized,
		}).Warn("Some eBPF monitors were disabled due to initialization errors")
	}

	return nil
}

func (l *Listener) initExecSource() error {
	if l.initExecFn != nil {
		return l.initExecFn()
	}
	return l.initExec()
}

func (l *Listener) initFileSource() error {
	if l.initFileFn != nil {
		return l.initFileFn()
	}
	return l.initFile()
}

func (l *Listener) initNetSource() error {
	if l.initNetFn != nil {
		return l.initNetFn()
	}
	return l.initNet()
}

func (l *Listener) initBpfSource() error {
	if l.initBpfFn != nil {
		return l.initBpfFn()
	}
	return l.initBpf()
}

// initExec loads the exec monitor BPF program and attaches to sched_process_exec.
func (l *Listener) initExec() error {
	objs := &execMonitorObjects{}
	if err := loadExecMonitorObjects(objs, nil); err != nil {
		return classifyBPFError(err, "exec_monitor")
	}
	if err := l.registerSelfPID(objs.SelfPids, "exec"); err != nil {
		objs.Close()
		return err
	}

	lnk, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceSchedProcessExec, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attaching sched_process_exec: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		lnk.Close()
		objs.Close()
		return fmt.Errorf("creating exec ring buffer reader: %w", err)
	}

	l.execObjs = objs
	l.execLink = lnk
	l.execReader = rd

	return nil
}

// initFile loads the file monitor BPF program and attaches to openat enter/exit.
func (l *Listener) initFile() error {
	objs := &fileMonitorObjects{}
	if err := loadFileMonitorObjects(objs, nil); err != nil {
		return classifyBPFError(err, "file_monitor")
	}
	if err := l.registerSelfPID(objs.SelfPids, "file"); err != nil {
		objs.Close()
		return err
	}

	enter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attaching sys_enter_openat: %w", err)
	}

	exit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TraceSysExitOpenat, nil)
	if err != nil {
		enter.Close()
		objs.Close()
		return fmt.Errorf("attaching sys_exit_openat: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		exit.Close()
		enter.Close()
		objs.Close()
		return fmt.Errorf("creating file ring buffer reader: %w", err)
	}

	l.fileObjs = objs
	l.fileEnter = enter
	l.fileExit = exit
	l.fileReader = rd

	return nil
}

// initNet loads the network monitor BPF program and attaches to inet_sock_set_state.
func (l *Listener) initNet() error {
	objs := &netMonitorObjects{}
	if err := loadNetMonitorObjects(objs, nil); err != nil {
		return classifyBPFError(err, "net_monitor")
	}
	if err := l.registerSelfPID(objs.SelfPids, "net"); err != nil {
		objs.Close()
		return err
	}

	lnk, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attaching inet_sock_set_state: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.NetEvents)
	if err != nil {
		lnk.Close()
		objs.Close()
		return fmt.Errorf("creating net ring buffer reader: %w", err)
	}

	l.netObjs = objs
	l.netLink = lnk
	l.netReader = rd

	return nil
}

// initBpf loads the bpf monitor BPF program and attaches to bpf enter/exit.
func (l *Listener) initBpf() error {
	objs := &bpfMonitorObjects{}
	if err := loadBpfMonitorObjects(objs, nil); err != nil {
		return classifyBPFError(err, "bpf_monitor")
	}
	if err := l.registerSelfPID(objs.SelfPids, "bpf"); err != nil {
		objs.Close()
		return err
	}

	enter, err := link.Tracepoint("syscalls", "sys_enter_bpf", objs.TraceSysEnterBpf, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attaching sys_enter_bpf: %w", err)
	}

	exit, err := link.Tracepoint("syscalls", "sys_exit_bpf", objs.TraceSysExitBpf, nil)
	if err != nil {
		enter.Close()
		objs.Close()
		return fmt.Errorf("attaching sys_exit_bpf: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.BpfEvents)
	if err != nil {
		exit.Close()
		enter.Close()
		objs.Close()
		return fmt.Errorf("creating bpf ring buffer reader: %w", err)
	}

	l.bpfObjs = objs
	l.bpfEnter = enter
	l.bpfExit = exit
	l.bpfReader = rd

	return nil
}

func (l *Listener) registerSelfPID(m *ebpf.Map, source string) error {
	if m == nil {
		return fmt.Errorf("registering self PID for %s monitor: self_pids map is nil", source)
	}

	const marker uint8 = 1
	if err := m.Put(l.selfPID, marker); err != nil {
		return fmt.Errorf("registering self PID for %s monitor: %w", source, err)
	}

	return nil
}

// SendEvents starts reading events from all enabled ring buffers and calls
// the callback for each parsed event. This method blocks until Close() is called.
func (l *Listener) SendEvents(callback func(event provider.Event)) {
	if l.enableExec && l.execReader != nil {
		l.wg.Add(1)
		go l.readExecEvents(callback)
	}
	if l.enableFile && l.fileReader != nil {
		l.wg.Add(1)
		go l.readFileEvents(callback)
	}
	if l.enableNet && l.netReader != nil {
		l.wg.Add(1)
		go l.readNetEvents(callback)
	}
	if l.enableBpf && l.bpfReader != nil {
		l.wg.Add(1)
		go l.readBpfEvents(callback)
	}

	l.wg.Wait()
}

// readExecEvents reads from the exec ring buffer and processes events.
func (l *Listener) readExecEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	var record ringbuf.Record
	for {
		err := l.execReader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading exec ring buffer")
			if l.closed.Load() {
				return
			}
			time.Sleep(readErrorBackoff)
			continue
		}

		evt, err := l.parseExecEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing exec event")
			continue
		}

		callback(evt)
	}
}

// readFileEvents reads from the file ring buffer and processes events.
func (l *Listener) readFileEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	var record ringbuf.Record
	for {
		err := l.fileReader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading file ring buffer")
			if l.closed.Load() {
				return
			}
			time.Sleep(readErrorBackoff)
			continue
		}

		evt, err := l.parseFileEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing file event")
			continue
		}

		callback(evt)
	}
}

// readNetEvents reads from the network ring buffer and processes events.
func (l *Listener) readNetEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	var record ringbuf.Record
	for {
		err := l.netReader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading net ring buffer")
			if l.closed.Load() {
				return
			}
			time.Sleep(readErrorBackoff)
			continue
		}

		evt, err := l.parseNetEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing net event")
			continue
		}

		callback(evt)
	}
}

// readBpfEvents reads from the bpf ring buffer and processes events.
func (l *Listener) readBpfEvents(callback func(event provider.Event)) {
	defer l.wg.Done()

	var record ringbuf.Record
	for {
		err := l.bpfReader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Error("Reading bpf ring buffer")
			if l.closed.Load() {
				return
			}
			time.Sleep(readErrorBackoff)
			continue
		}

		evt, err := l.parseBpfEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Parsing bpf event")
			continue
		}

		callback(evt)
	}
}

// BPF binary structs for parsing ring buffer records.

type bpfExecEvent struct {
	TimestampNs uint64
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	Comm        [16]byte
	Filename    [256]byte
	FilenameLen uint32
}

type bpfFileEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Dfd         int32
	Flags       uint32
	Filename    [256]byte
	FilenameLen uint32
}

type bpfNetEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Sport       uint16
	Dport       uint16
	Saddr       [16]byte
	Daddr       [16]byte
	Family      uint8
	Initiated   uint8
	Pad         uint16
}

type bpfBpfEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Cmd         uint32
	ProgType    uint32
	RetVal      int64
	ProgName    [16]byte
}

// parseExecEvent parses a raw exec event from the ring buffer and reconstructs
// all fields from /proc.
func (l *Listener) parseExecEvent(data []byte) (*ebpfEvent, error) {
	var raw bpfExecEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decoding exec event: %w", err)
	}

	pid := raw.Pid
	ppid := raw.Ppid
	uid := raw.Uid

	// Resolve Image from /proc/PID/exe, fallback to BPF filename
	bpfFilename := nullTermStr(raw.Filename[:], int(raw.FilenameLen))
	image, err := readExeLink(pid)
	if err != nil {
		image = bpfFilename
	}

	// Read command line
	var cmdline string
	var truncated bool
	cmdBytes, err := readCmdline(pid)
	if err == nil {
		cmdline, truncated = joinCmdline(cmdBytes)
	}

	// Read cwd
	cwd, _ := readCwd(pid)

	// Read loginuid
	loginUID := readLoginUID(pid)

	// Resolve username
	username := l.userCache.Lookup(uid)

	// Resolve parent from correlator, then /proc fallback
	var parentImage, parentCmdline string
	if l.correlator != nil {
		if info := l.correlator.Lookup(ppid); info != nil {
			parentImage = info.Image
			parentCmdline = info.CommandLine
		}
	}
	if parentImage == "" {
		parentImage, _ = readExeLink(ppid)
	}
	if parentCmdline == "" {
		if pCmdBytes, err := readCmdline(ppid); err == nil {
			parentCmdline, _ = joinCmdline(pCmdBytes)
		}
	}

	fields := buildExecFieldsMap(
		pid, ppid, uid,
		bpfFilename, image, cmdline, truncated,
		cwd, loginUID, username,
		parentImage, parentCmdline,
	)

	// Store in correlator for future parent lookups
	if l.correlator != nil {
		l.correlator.Store(pid, &enrichment.ProcessInfo{
			PID:              pid,
			Image:            image,
			CommandLine:      cmdline,
			User:             username,
			CurrentDirectory: cwd,
		})
	}

	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDProcessCreation,
		},
		pid:    pid,
		source: SourceProcessExec,
		ts:     l.ktimeToWall(raw.TimestampNs),
		fields: fields,
	}, nil
}

// parseFileEvent parses a raw file event and reconstructs fields.
func (l *Listener) parseFileEvent(data []byte) (*ebpfEvent, error) {
	var raw bpfFileEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decoding file event: %w", err)
	}

	pid := raw.Pid
	uid := raw.Uid
	filename := nullTermStr(raw.Filename[:], int(raw.FilenameLen))

	// Resolve filename to absolute path
	targetFilename := resolveFilename(pid, filename, raw.Dfd)

	// Resolve Image
	image, _ := readExeLink(pid)
	if image == "" && l.correlator != nil {
		if info := l.correlator.Lookup(pid); info != nil {
			image = info.Image
		}
	}

	username := l.userCache.Lookup(uid)

	fields := buildFileFieldsMap(pid, uid, targetFilename, image, username, raw.Flags)

	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDFileEvent,
		},
		pid:    pid,
		source: SourceFileCreate,
		ts:     l.ktimeToWall(raw.TimestampNs),
		fields: fields,
	}, nil
}

// parseNetEvent parses a raw network event and reconstructs fields.
func (l *Listener) parseNetEvent(data []byte) (*ebpfEvent, error) {
	var raw bpfNetEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decoding net event: %w", err)
	}

	pid := raw.Pid
	uid := raw.Uid

	// Resolve Image
	image, _ := readExeLink(pid)
	if image == "" && l.correlator != nil {
		if info := l.correlator.Lookup(pid); info != nil {
			image = info.Image
		}
	}

	username := l.userCache.Lookup(uid)

	// Format IP addresses
	const afInet = 2
	var srcIP, dstIP string
	if raw.Family == afInet {
		srcIP = formatIPv4(raw.Saddr)
		dstIP = formatIPv4(raw.Daddr)
	} else {
		srcIP = formatIPv6(raw.Saddr)
		dstIP = formatIPv6(raw.Daddr)
	}

	initiated := raw.Initiated == 1

	fields := buildNetFieldsMap(
		pid, uid, image, username,
		srcIP, raw.Sport, dstIP, raw.Dport,
		initiated,
	)

	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDNetworkConnection,
		},
		pid:    pid,
		source: SourceNetConnect,
		ts:     l.ktimeToWall(raw.TimestampNs),
		fields: fields,
	}, nil
}

// parseBpfEvent parses a raw bpf syscall event and reconstructs fields.
func (l *Listener) parseBpfEvent(data []byte) (*ebpfEvent, error) {
	var raw bpfBpfEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decoding bpf event: %w", err)
	}

	pid := raw.Pid
	uid := raw.Uid

	// Resolve Image
	image, _ := readExeLink(pid)
	if image == "" && l.correlator != nil {
		if info := l.correlator.Lookup(pid); info != nil {
			image = info.Image
		}
	}

	username := l.userCache.Lookup(uid)

	fields := buildBpfFieldsMap(
		pid, uid, image, username,
		raw.Cmd, raw.ProgType, raw.RetVal,
		nullTermStr(raw.ProgName[:], len(raw.ProgName)),
	)

	return &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: ProviderName,
			EventID:      EventIDBpfEvent,
		},
		pid:    pid,
		source: SourceBpfEvent,
		ts:     l.ktimeToWall(raw.TimestampNs),
		fields: fields,
	}, nil
}

// LostEvents returns the total number of lost events across all enabled sources.
func (l *Listener) LostEvents() uint64 {
	var total uint64

	if l.execObjs != nil {
		total += readLostCounter(l.execObjs.LostEvents)
	}
	if l.fileObjs != nil {
		total += readLostCounter(l.fileObjs.FileLostEvents)
	}
	if l.netObjs != nil {
		total += readLostCounter(l.netObjs.NetLostEvents)
	}
	if l.bpfObjs != nil {
		total += readLostCounter(l.bpfObjs.BpfLostEvents)
	}

	return total
}

// Close tears down all BPF programs and ring buffer readers.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}

	var closeErrs []error

	// Close readers first to unblock Read() calls
	if l.execReader != nil {
		if err := l.execReader.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing exec reader: %w", err))
		}
	}
	if l.fileReader != nil {
		if err := l.fileReader.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing file reader: %w", err))
		}
	}
	if l.netReader != nil {
		if err := l.netReader.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing net reader: %w", err))
		}
	}
	if l.bpfReader != nil {
		if err := l.bpfReader.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing bpf reader: %w", err))
		}
	}

	// Detach tracepoints
	if l.execLink != nil {
		if err := l.execLink.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing exec link: %w", err))
		}
	}
	if l.fileEnter != nil {
		if err := l.fileEnter.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing file enter link: %w", err))
		}
	}
	if l.fileExit != nil {
		if err := l.fileExit.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing file exit link: %w", err))
		}
	}
	if l.netLink != nil {
		if err := l.netLink.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing net link: %w", err))
		}
	}
	if l.bpfEnter != nil {
		if err := l.bpfEnter.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing bpf enter link: %w", err))
		}
	}
	if l.bpfExit != nil {
		if err := l.bpfExit.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing bpf exit link: %w", err))
		}
	}

	// Close BPF objects
	if l.execObjs != nil {
		if err := l.execObjs.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing exec objects: %w", err))
		}
	}
	if l.fileObjs != nil {
		if err := l.fileObjs.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing file objects: %w", err))
		}
	}
	if l.netObjs != nil {
		if err := l.netObjs.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing net objects: %w", err))
		}
	}
	if l.bpfObjs != nil {
		if err := l.bpfObjs.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("closing bpf objects: %w", err))
		}
	}

	return errors.Join(closeErrs...)
}

// ktimeToWall converts a BPF ktime_get_ns() timestamp to wall clock time.
func (l *Listener) ktimeToWall(ktimeNs uint64) time.Time {
	wallNs := l.bootNanos + int64(ktimeNs)
	return time.Unix(0, wallNs)
}

// bootTimeNanos computes the wall-clock time of system boot in nanoseconds.
func bootTimeNanos() int64 {
	// Boot time = now - monotonic uptime
	// This is an approximation; for higher precision we could read /proc/stat btime.
	now := time.Now()
	var uptimeNs int64

	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return now.UnixNano()
	}

	// /proc/uptime: "seconds.centiseconds idle.centiseconds"
	fields := bytes.Fields(data)
	if len(fields) < 1 {
		return now.UnixNano()
	}

	// Parse the uptime seconds as float
	var secs, frac int64
	parts := bytes.SplitN(fields[0], []byte("."), 2)
	for _, b := range parts[0] {
		secs = secs*10 + int64(b-'0')
	}
	if len(parts) > 1 {
		// Parse fractional part (centiseconds → nanoseconds)
		fracStr := parts[1]
		for _, b := range fracStr {
			frac = frac*10 + int64(b-'0')
		}
		// Scale fractional part to nanoseconds
		scale := int64(1)
		for i := 0; i < 9-len(fracStr); i++ {
			scale *= 10
		}
		frac *= scale
	}

	uptimeNs = secs*1e9 + frac
	return now.UnixNano() - uptimeNs
}

// nullTermStr extracts a NUL-terminated string from a fixed byte array.
func nullTermStr(b []byte, maxLen int) string {
	if maxLen <= 0 || maxLen > len(b) {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		if b[i] == 0 {
			return string(b[:i])
		}
	}
	return string(b[:maxLen])
}

// readLostCounter reads the single-entry BPF array map used as a lost event counter.
func readLostCounter(m *ebpf.Map) uint64 {
	if m == nil {
		return 0
	}
	var key uint32
	var count uint64
	if err := m.Lookup(&key, &count); err != nil {
		return 0
	}
	return count
}

// classifyBPFError wraps a BPF loading error with an actionable message.
func classifyBPFError(err error, program string) error {
	errStr := err.Error()

	switch {
	case contains(errStr, "unknown func") || contains(errStr, "BTF"):
		return fmt.Errorf(
			"loading %s: kernel too old or BTF disabled. "+
				"eBPF requires kernel 5.2+ with BTF. %w", program, err)
	case contains(errStr, "EPERM") || contains(errStr, "operation not permitted"):
		return fmt.Errorf(
			"loading %s: insufficient privileges. "+
				"Requires CAP_BPF+CAP_PERFMON (5.8+) or CAP_SYS_ADMIN (5.2-5.7) or root. %w", program, err)
	case contains(errStr, "ENOMEM"):
		return fmt.Errorf(
			"loading %s: memory limit too low. "+
				"Set LimitMEMLOCK=infinity in the systemd unit. %w", program, err)
	case contains(errStr, "EBUSY"):
		return fmt.Errorf(
			"loading %s: tracepoint is busy. "+
				"Another eBPF agent may be running. %w", program, err)
	default:
		return fmt.Errorf("loading %s: %w", program, err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && bytes.Contains([]byte(s), []byte(substr))
}
