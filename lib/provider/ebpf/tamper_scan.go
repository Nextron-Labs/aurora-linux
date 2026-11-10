package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// dangerousHelpers are BPF helpers that let a program tamper with other
// processes or with the kernel's behaviour, i.e. blind a monitoring agent.
var dangerousHelpers = map[asm.BuiltinFunc]string{
	asm.FnProbeWriteUser:   "bpf_probe_write_user",
	asm.FnOverrideReturn:   "bpf_override_return",
	asm.FnSendSignal:       "bpf_send_signal",
	asm.FnSendSignalThread: "bpf_send_signal_thread",
}

// tracingProgTypes can attach to the same hooks as Aurora's sensors.
var tracingProgTypes = map[ebpf.ProgramType]bool{
	ebpf.Kprobe: true, ebpf.TracePoint: true, ebpf.RawTracepoint: true,
	ebpf.RawTracepointWritable: true, ebpf.Tracing: true, ebpf.LSM: true,
	ebpf.PerfEvent: true, ebpf.Extension: true,
}

// helperImmNames maps the call immediates the kernel reports in dumped
// instructions to dangerous helper names. Many kernels expose helper calls as
// (function address - __bpf_call_base) instead of the helper ID, so the
// addresses are resolved through /proc/kallsyms (needs root/CAP_SYSLOG).
var helperImmNames = sync.OnceValue(func() map[int64]string {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseHelperImms(f)
})

func parseHelperImms(r io.Reader) map[int64]string {
	want := map[string]bool{"__bpf_call_base": true}
	for _, n := range dangerousHelpers {
		want[n] = true
	}
	addrs := map[string]uint64{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || !want[fields[2]] {
			continue
		}
		if a, err := strconv.ParseUint(fields[0], 16, 64); err == nil && a != 0 {
			addrs[fields[2]] = a
		}
	}
	base, ok := addrs["__bpf_call_base"]
	if !ok {
		return nil
	}
	out := map[int64]string{}
	for _, n := range dangerousHelpers {
		if a, ok := addrs[n]; ok {
			out[int64(int32(a-base))] = n
		}
	}
	return out
}

// helpersUsed lists the dangerous helpers an instruction stream calls.
func helpersUsed(insns asm.Instructions) []string {
	return helpersUsedWith(insns, helperImmNames())
}

func helpersUsedWith(insns asm.Instructions, immNames map[int64]string) []string {
	found := map[string]bool{}
	for _, ins := range insns {
		if !ins.IsBuiltinCall() {
			continue
		}
		if name, ok := dangerousHelpers[asm.BuiltinFunc(ins.Constant)]; ok {
			found[name] = true
		}
		if name, ok := immNames[ins.Constant]; ok {
			found[name] = true
		}
	}
	out := make([]string, 0, len(found))
	for n := range found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// BPFWatcher inventories eBPF programs loaded by other parties and alerts on
// ones that can interfere with Aurora.
type BPFWatcher struct {
	mu   sync.Mutex
	own  map[ebpf.ProgramID]bool
	seen map[ebpf.ProgramID]bool
}

// NewBPFWatcher creates a watcher that treats ownIDs as Aurora's programs.
func NewBPFWatcher(ownIDs []uint32) *BPFWatcher {
	w := &BPFWatcher{own: map[ebpf.ProgramID]bool{}, seen: map[ebpf.ProgramID]bool{}}
	for _, id := range ownIDs {
		w.own[ebpf.ProgramID(id)] = true
	}
	return w
}

// Scan enumerates loaded programs and reports every not yet seen foreign
// program that is tracing-class or uses a dangerous helper. baseline marks
// the first scan: pre-existing benign programs are only inventoried, but
// pre-existing programs with dangerous helpers still alert.
// Scan enumerates loaded programs and reports every not yet seen foreign
// program that is tracing-class or uses a dangerous helper. On the baseline
// (first) scan, benign tracing programs loaded before since are only
// inventoried; ones loaded after since (e.g. while Aurora was restarting)
// and ones with dangerous helpers are reported.
func (w *BPFWatcher) Scan(baseline bool, since time.Time, alert func(TamperAlert)) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var id ebpf.ProgramID
	present := make(map[ebpf.ProgramID]bool, len(w.seen))
	complete := false
	defer func() {
		// Forget programs that unloaded so the set cannot grow without bound
		// on hosts that churn eBPF programs. Only after a complete scan: a
		// partial one would make still-loaded programs alert again.
		if !complete {
			return
		}
		for sid := range w.seen {
			if !present[sid] {
				delete(w.seen, sid)
			}
		}
	}()
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				complete = true
				return nil
			}
			return err
		}
		present[next] = true
		id = next
		if w.own[id] || w.seen[id] {
			continue
		}

		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				w.seen[id] = true // unloaded meanwhile
			}
			continue // transient (e.g. EMFILE): retry on the next scan
		}
		a, ok, inspected := w.inspect(p, id, baseline, since)
		p.Close()
		if !inspected {
			continue
		}
		w.seen[id] = true
		if ok {
			alert(a)
		}
	}
}

func (w *BPFWatcher) inspect(p *ebpf.Program, id ebpf.ProgramID, baseline bool, since time.Time) (a TamperAlert, report, inspected bool) {
	info, err := p.Info()
	if err != nil {
		return TamperAlert{}, false, false
	}
	var helpers []string
	if insns, err := info.Instructions(); err == nil {
		helpers = helpersUsed(insns)
	}
	tracing := tracingProgTypes[info.Type]
	quietBaseline := baseline
	if baseline && !since.IsZero() {
		if lt, ok := info.LoadTime(); ok && time.Unix(0, bootTimeNanos()+int64(lt)).After(since) {
			quietBaseline = false // loaded during Aurora's restart window
		}
	}
	if len(helpers) == 0 && (!tracing || quietBaseline) {
		return TamperAlert{}, false, true
	}

	f := map[string]string{
		"bpf_prog_id":   fmt.Sprint(uint32(id)),
		"bpf_prog_name": info.Name,
		"bpf_prog_type": info.Type.String(),
	}
	if tag := info.Tag; tag != "" {
		f["bpf_prog_tag"] = tag
	}
	if uid, ok := info.CreatedByUID(); ok {
		f["bpf_loaded_by_uid"] = fmt.Sprint(uid)
	}
	if lt, ok := info.LoadTime(); ok {
		f["bpf_loaded_at"] = time.Unix(0, bootTimeNanos()+int64(lt)).UTC().Format(time.RFC3339)
	}
	a = TamperAlert{Time: time.Now(), Fields: f}
	if len(helpers) > 0 {
		f["bpf_dangerous_helpers"] = strings.Join(helpers, ",")
		a.Kind = "foreign-bpf-dangerous"
		a.Severity = SeverityCritical
		a.Message = fmt.Sprintf("Third-party eBPF program %q (id %d, %s) uses %s: it can alter or blind monitoring",
			info.Name, id, info.Type, strings.Join(helpers, ", "))
		return a, true, true
	}
	a.Kind = "foreign-bpf-tracing"
	a.Severity = SeverityMedium
	a.Message = fmt.Sprintf("Third-party %s eBPF program %q (id %d) was loaded while Aurora is running", info.Type, info.Name, id)
	return a, true, true
}
