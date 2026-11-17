package ebpf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	"github.com/cilium/ebpf/asm"
)

func TestHelpersUsedByIDAndKallsymsImm(t *testing.T) {
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.FnProbeWriteUser.Call(),
		asm.FnKtimeGetNs.Call(),
		{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: -206336},
		asm.Return(),
	}
	got := helpersUsedWith(insns, map[int64]string{-206336: "bpf_override_return"})
	if strings.Join(got, ",") != "bpf_override_return,bpf_probe_write_user" {
		t.Fatalf("helpers = %v", got)
	}
	if got := helpersUsedWith(asm.Instructions{asm.FnKtimeGetNs.Call(), asm.Return()}, nil); len(got) != 0 {
		t.Fatalf("benign program flagged: %v", got)
	}
}

func TestParseHelperImms(t *testing.T) {
	ks := "ffffffff81000000 T __bpf_call_base\nffffffff81000100 T bpf_probe_write_user\nffffffff80ff0000 T bpf_send_signal\nffffffff81000200 t unrelated\n"
	m := parseHelperImms(strings.NewReader(ks))
	if m[0x100] != "bpf_probe_write_user" || m[-0x10000] != "bpf_send_signal" || len(m) != 2 {
		t.Fatalf("imms = %v", m)
	}
	if parseHelperImms(strings.NewReader("0000000000000000 T __bpf_call_base\n")) != nil {
		t.Fatal("hidden kallsyms addresses must yield no map")
	}
}

type fakeEvt struct {
	src    string
	pid    uint32
	fields enrichment.DataFieldsMap
}

func (e *fakeEvt) ID() provider.EventIdentifier        { return provider.EventIdentifier{} }
func (e *fakeEvt) Process() uint32                     { return e.pid }
func (e *fakeEvt) Source() string                      { return e.src }
func (e *fakeEvt) Time() time.Time                     { return time.Time{} }
func (e *fakeEvt) Value(k string) enrichment.DataValue { return e.fields.Value(k) }
func (e *fakeEvt) ForEach(fn func(k, v string))        { e.fields.ForEach(fn) }

func TestCanaryObserveClaimsOnlyByPid(t *testing.T) {
	c := &Canary{}
	mk := func(src string, pid uint32, kv ...string) *fakeEvt {
		f := enrichment.DataFieldsMap{}
		for i := 0; i < len(kv); i += 2 {
			f.AddField(kv[i], kv[i+1])
		}
		return &fakeEvt{src: src, pid: pid, fields: f}
	}
	if c.Observe(mk(SourceProcessExec, 77, "CommandLine", "ls")) {
		t.Fatal("no canary running: must not claim events")
	}
	c.run = &canaryRun{pid: 77, seen: map[string]bool{}}
	c.active.Store(true)
	// Content that looks like the canary must not hide another process.
	if c.Observe(mk(SourceProcessExec, 5, "CommandLine", "aurora __aurora_canary_stage2__")) {
		t.Fatal("event of another pid claimed because of its content")
	}
	if !c.Observe(mk(SourceProcessExec, 77, "CommandLine", "aurora-canary __aurora_canary_stage2__")) {
		t.Fatal("exec canary event not claimed")
	}
	if !c.Observe(mk(SourceNetConnect, 77, "DestinationPort", "9")) {
		t.Fatal("net canary event not claimed")
	}
	if !c.Observe(mk(SourceAudit, 77, "SYSCALL", "sysinfo")) {
		t.Fatal("audit canary event not claimed")
	}
	for _, s := range []string{SourceProcessExec, SourceNetConnect, SourceAudit} {
		if !c.run.seen[s] {
			t.Errorf("source %s not marked seen", s)
		}
	}
	if c.run.seen[SourceFileCreate] {
		t.Error("file source must not be marked seen")
	}
	// Grace period after the round: late helper events stay hidden.
	c.run = nil
	c.lastPid, c.lastUntil = 77, time.Now().Add(time.Second)
	if !c.Observe(mk(SourceAudit, 77, "SYSCALL", "connect")) {
		t.Fatal("late helper event leaked")
	}
	if c.Observe(mk(SourceAudit, 78, "SYSCALL", "connect")) {
		t.Fatal("unrelated event claimed during grace")
	}
}

func TestCanaryNonceValidation(t *testing.T) {
	if validNonce("../../etc/x") || validNonce("") || !validNonce("0123456789abcdef") {
		t.Fatal("nonce validation")
	}
}

func TestRunStateDetectsUncleanExit(t *testing.T) {
	rs := RunState{Path: t.TempDir() + "/run/state"}
	if p := rs.Begin(); p.UncleanPid != 0 {
		t.Fatalf("first start reported unclean pid %d", p.UncleanPid)
	}
	p := rs.Begin()
	if p.UncleanPid == 0 || p.PrevStart.IsZero() {
		t.Fatalf("second start without End must report the unclean previous run: %+v", p)
	}
	rs.End()
	if p := rs.Begin(); p.UncleanPid != 0 || p.PrevStart.IsZero() {
		t.Fatalf("after clean End: %+v (start time must be kept)", p)
	}
}

func TestTamperAlertClassification(t *testing.T) {
	s := &TamperSensor{pid: 100}
	e := &bpfTamperEvent{Kind: tkSignal, Pid: 4242, Arg: 9, Target: 100}
	copy(e.Comm[:], "evilkill")
	a := s.buildAlert(e, false)
	if a.Kind != "signal" || a.Severity != SeverityCritical || !strings.Contains(a.Message, "SIGKILL") {
		t.Fatalf("alert = %+v", a)
	}
	e = &bpfTamperEvent{Kind: tkSignal, Pid: 1, Arg: 15}
	if a := s.buildAlert(e, false); a.Severity != SeverityMedium {
		t.Fatalf("systemd SIGTERM severity = %s", a.Severity)
	}
	// LSM stream: kinds are mapped before buildAlert; reports blocked=true.
	e = &bpfTamperEvent{Kind: lsmKinds[3], Pid: 9, Arg: 30}
	a = s.buildAlert(e, true)
	if a.Kind != "bpf-management" || a.Fields["blocked"] != "true" || !strings.Contains(a.Message, "BPF_LINK_GET_FD_BY_ID") {
		t.Fatalf("lsm alert = %+v", a)
	}
}

func TestTamperAlertDedup(t *testing.T) {
	s := &TamperSensor{}
	t0 := time.Now()
	if ok, _ := s.admit("k", t0); !ok {
		t.Fatal("first alert must be emitted")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := s.admit("k", t0.Add(time.Second)); ok {
			t.Fatal("repeat inside window must be folded")
		}
	}
	if ok, n := s.admit("k", t0.Add(dedupWindow+time.Second)); !ok || n != 5 {
		t.Fatalf("after window: ok=%v folded=%d, want true/5", ok, n)
	}
	if ok, _ := s.admit("other", t0); !ok {
		t.Fatal("different key must not be folded")
	}
}

// The hand-written decoders must agree with encoding/binary on the C layout.
func TestDecodersMatchBinaryRead(t *testing.T) {
	fill := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*7 + 3)
		}
		return b
	}
	var a1, a2 bpfAuditEvent
	data := fill(auditEventSize)
	if err := decodeAuditEvent(data, &a1); err != nil {
		t.Fatal(err)
	}
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &a2); err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Error("audit decoder differs from binary.Read")
	}
	var e1, e2 bpfExecEvent
	data = fill(execEventSize + auditArgsMax) // full args
	binary.LittleEndian.PutUint32(data[308:], auditArgsMax)
	if err := decodeExecEvent(data, &e1); err != nil {
		t.Fatal(err)
	}
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e2); err != nil {
		t.Fatal(err)
	}
	if e1 != e2 {
		t.Error("exec decoder differs from binary.Read")
	}
	// Variable length: only args_len bytes follow the header; a stale
	// longer args_len must not read past the record.
	short := append(fill(execEventSize), "ls\x00-l\x00"...)
	binary.LittleEndian.PutUint32(short[308:], 4000)
	var e3 bpfExecEvent
	if err := decodeExecEvent(short, &e3); err != nil {
		t.Fatal(err)
	}
	if e3.ArgsLen != 6 || string(e3.Args[:6]) != "ls\x00-l\x00" || e3.StartNs != e1.StartNs {
		t.Errorf("short exec record: len=%d args=%q", e3.ArgsLen, e3.Args[:8])
	}
	var h1, h2 bpfHookEvent
	data = fill(hookEventSize)
	if err := decodeHookEvent(data, &h1); err != nil {
		t.Fatal(err)
	}
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &h2); err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("hook decoder differs from binary.Read")
	}
	var t1, t2 bpfTamperEvent
	data = fill(tamperEventSize + tamperPathBytes)
	if err := decodeTamperEvent(data, &t1); err != nil {
		t.Fatal(err)
	}
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &t2); err != nil {
		t.Fatal(err)
	}
	if t1 != t2 {
		t.Error("tamper decoder differs from binary.Read")
	}
	var f1, f2 bpfFileEvent
	data = fill(fileEventSize)
	if err := decodeFileEvent(data, &f1); err != nil {
		t.Fatal(err)
	}
	_ = binary.Read(bytes.NewReader(data), binary.LittleEndian, &f2)
	if f1 != f2 {
		t.Error("file decoder differs from binary.Read")
	}
	var n1, n2 bpfNetEvent
	data = fill(netEventSize)
	if err := decodeNetEvent(data, &n1); err != nil {
		t.Fatal(err)
	}
	_ = binary.Read(bytes.NewReader(data), binary.LittleEndian, &n2)
	if n1 != n2 {
		t.Error("net decoder differs from binary.Read")
	}
	var b1, b2 bpfBpfEvent
	data = fill(bpfEventSize)
	if err := decodeBpfEvent(data, &b1); err != nil {
		t.Fatal(err)
	}
	_ = binary.Read(bytes.NewReader(data), binary.LittleEndian, &b2)
	if b1 != b2 {
		t.Error("bpf decoder differs from binary.Read")
	}
	if err := decodeAuditEvent(make([]byte, 10), &a1); err == nil {
		t.Error("short audit record accepted")
	}
}

func BenchmarkDecodeAuditEvent(b *testing.B) {
	data := make([]byte, auditEventSize)
	var e bpfAuditEvent
	for i := 0; i < b.N; i++ {
		_ = decodeAuditEvent(data, &e)
	}
}

func BenchmarkBinaryReadAuditEvent(b *testing.B) {
	data := make([]byte, auditEventSize)
	var e bpfAuditEvent
	for i := 0; i < b.N; i++ {
		_ = binary.Read(bytes.NewReader(data), binary.LittleEndian, &e)
	}
}

func TestParseStatStartTicksAndMatch(t *testing.T) {
	// comm contains spaces and a ')' on purpose.
	stat := "1234 (we ird) name) S 1 1234 1234 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615"
	got, ok := parseStatStartTicks(stat)
	if !ok || got != 987654 {
		t.Fatalf("start ticks = %d, %v", got, ok)
	}
	if _, ok := parseStatStartTicks("garbage"); ok {
		t.Fatal("garbage accepted")
	}
	if !startMatches(987654, 987654*clockTickNs+clockTickNs/2) {
		t.Error("same process rejected")
	}
	if startMatches(987654, 987655*clockTickNs+5*clockTickNs) {
		t.Error("reused pid (different start time) accepted")
	}
}

func TestIdentityCachePrefersExactMatchOverProc(t *testing.T) {
	ic := newIdentityCache(8)
	ic.put(4242, procIdentity{startNs: 1111, exe: "/usr/bin/nc", auid: "1000"})
	// pid 4242 does not exist here; the cache must answer for the right start time.
	if exe, auid := ic.resolve(4242, 1111, 0); exe != "/usr/bin/nc" || auid != "1000" {
		t.Fatalf("cache miss: %q %q", exe, auid)
	}
	// Same process re-exec'd (newer exec generation): the cached exe is stale.
	ic.put(4243, procIdentity{startNs: 5, execID: 1, exe: "/bin/bash", auid: "0"})
	if exe, _ := ic.resolve(4243, 5, 2); exe == "/bin/bash" {
		t.Fatal("stale identity returned after re-exec")
	}
	// Same pid, different start time (pid reuse): must not return the old exe.
	if exe, _ := ic.resolve(4242, 2222, 0); exe == "/usr/bin/nc" {
		t.Fatal("stale identity returned for a reused pid")
	}
}

func TestCanarySpawnWindowAndStage2Proof(t *testing.T) {
	c := &Canary{AuroraPid: 1000}
	mk := func(src string, pid uint32, kv ...string) *fakeEvt {
		f := enrichment.DataFieldsMap{}
		for i := 0; i < len(kv); i += 2 {
			f.AddField(kv[i], kv[i+1])
		}
		return &fakeEvt{src: src, pid: pid, fields: f}
	}
	c.active.Store(true)
	c.spawning = true
	// The helper's first exec (parent = Aurora) is hidden and its pid learned.
	if !c.Observe(mk(SourceProcessExec, 4242, "ParentProcessId", "1000", "CommandLine", "aurora __aurora_canary__")) {
		t.Fatal("stage-1 exec leaked as telemetry")
	}
	if c.spawnPid != 4242 {
		t.Fatalf("spawnPid = %d", c.spawnPid)
	}
	// Other processes are unaffected, even with a canary-like command line.
	if c.Observe(mk(SourceProcessExec, 5, "ParentProcessId", "1", "CommandLine", "aurora __aurora_canary__")) {
		t.Fatal("unrelated exec claimed during spawn")
	}
	// After registration, only the stage-2 exec proves the exec source.
	c.spawning = false
	c.run = &canaryRun{pid: 4242, seen: map[string]bool{}}
	c.Observe(mk(SourceProcessExec, 4242, "CommandLine", "aurora __aurora_canary__"))
	if c.run.seen[SourceProcessExec] {
		t.Fatal("stage-1 exec counted as proof")
	}
	c.Observe(mk(SourceProcessExec, 4242, "CommandLine", "aurora-canary "+CanaryStage2Arg))
	if !c.run.seen[SourceProcessExec] {
		t.Fatal("stage-2 exec not counted")
	}
}
