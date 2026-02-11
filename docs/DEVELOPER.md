# Aurora Linux -- Developer Guide

This document is written for an LLM or developer picking up this codebase.
It explains what Aurora Linux is, how the code is organized, what design
decisions were made (and why), what currently works, and what remains to be
done. Read this before touching any source file.

---

## 1. What Is Aurora Linux?

Aurora Linux is a standalone, open-source Linux EDR (Endpoint Detection &
Response) agent. It:

1. Collects system telemetry in real time via **eBPF** tracepoints in the kernel.
2. Normalizes each event into a flat key-value schema that Sigma rules understand.
3. Evaluates events against **Sigma rules** and emits alerts on match.

It is inspired by the Windows-based Aurora agent (which uses ETW + Sigma) but
shares **zero code** with it. This is an entirely separate Go codebase.

### Target environment

- Linux kernel 5.8+ recommended (5.2+ with degraded support).
- Runs as root (or with CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE).
- Deployed as a systemd service.

---

## 2. Repository Layout

```
aurora-linux/
├── cmd/aurora-linux/            CLI entry point
│   ├── main.go                  Cobra root command, flag definitions
│   └── agent/
│       ├── agent.go             Agent lifecycle: init → collect → shutdown
│       ├── parameters.go        Configuration struct + defaults
│       ├── validate.go          Startup parameter validation (user-facing errors)
│       └── *_test.go            Agent lifecycle + validation tests
├── lib/
│   ├── provider/
│   │   ├── provider.go          EventProvider + Event interfaces
│   │   ├── ebpf/                eBPF provider (the main telemetry source)
│   │   │   ├── bpf/             BPF C programs (compiled with bpf2go)
│   │   │   │   ├── exec_monitor.c   process creation tracepoint
│   │   │   │   ├── file_monitor.c   file creation tracepoints (openat)
│   │   │   │   └── net_monitor.c    network connection tracepoint
│   │   │   ├── generate.go      //go:generate directives for bpf2go
│   │   │   ├── bpf_stubs.go    Non-Linux stubs (build tag: !linux)
│   │   │   ├── listener.go      eBPF Listener: load, attach, read ring buffers
│   │   │   ├── event.go         ebpfEvent struct (implements provider.Event)
│   │   │   ├── fieldmap.go      Builds DataFieldsMap for each event type
│   │   │   ├── fieldmap_test.go Unit tests for field mapping
│   │   │   ├── procfs.go        /proc/PID/* helpers
│   │   │   └── usercache.go     UID→username LRU cache
│   │   └── replay/
│   │       ├── replay.go        JSONL replay provider (for CI without BPF)
│   │       └── replay_test.go   Replay parsing/filtering/close tests
│   ├── distributor/
│   │   ├── distributor.go       Event routing + enrichment dispatch
│   │   ├── enrichments.go       Linux-specific enrichment registrations
│   │   └── *_test.go            Concurrency + enrichment tests
│   ├── enrichment/
│   │   ├── enricher.go          DataFields, DataFieldsMap, EventEnricher
│   │   ├── enricher_test.go
│   │   ├── correlator.go        LRU parent-process correlation cache
│   │   └── correlator_test.go
│   ├── consumer/sigma/
│   │   ├── sigmaconsumer.go     Sigma rule loading + evaluation + throttling
│   │   ├── loadrules.go         YAML file helpers
│   │   └── sigmaconsumer_test.go
│   └── logging/
│       ├── jsonformatter.go     JSON log output (for SIEM ingestion)
│       ├── textformatter.go     Human-readable log output
│       └── textformatter_test.go
├── resources/log-sources/
│   ├── ebpf-log-sources.yml             Service→provider source mapping
│   └── ebpf-log-source-mappings.yml     Sigma category→service mapping
├── deploy/
│   └── aurora-linux.service     systemd unit file
├── docs/
│   ├── plan_aurora_linux_ebpf_sigma.md  Full technical design document (1900+ lines)
│   └── DEVELOPER.md             This file
├── go.mod
└── go.sum
```

---

## 3. Data Flow (Event Pipeline)

```
KERNEL SPACE                                USER SPACE

┌────────────────────┐
│ BPF: sched_process │──┐
│      _exec         │  │
├────────────────────┤  │  ┌──────────┐   ┌────────────┐   ┌───────────┐
│ BPF: sys_{enter,   │──┼─▶│ Listener │──▶│Distributor │──▶│  Sigma    │──▶ log output
│    exit}_openat    │  │  │(listener │   │(distributor│   │ Consumer  │   (JSON/text)
├────────────────────┤  │  │  .go)    │   │  .go)      │   │(sigma-    │
│ BPF: inet_sock_    │──┘  │          │   │            │   │ consumer  │
│    set_state       │     │ Ring     │   │ Enrich +   │   │  .go)     │
└────────────────────┘     │ buffers  │   │ correlate  │   │           │
                           └──────────┘   └────────────┘   └───────────┘
```

### Step by step:

1. **BPF program** fires on a kernel tracepoint, populates a small struct
   (~64-300 bytes), submits it to a BPF ring buffer.
2. **Listener** (`listener.go`) has a goroutine per ring buffer. It reads
   the raw bytes, parses them into a Go struct (`bpfExecEvent` /
   `bpfFileEvent` / `bpfNetEvent`), then **reconstructs** rich fields by
   reading `/proc/PID/*` (exe, cmdline, cwd, loginuid) and looking up
   the UID→username cache.
3. The listener builds a `DataFieldsMap` with Sigma-compatible field names
   (e.g., `"Image"`, `"CommandLine"`, `"TargetFilename"`, `"DestinationIp"`)
   and wraps it in an `ebpfEvent` implementing `provider.Event`.
4. **Distributor** receives the event, applies registered **enrichment
   functions** (parent process correlation from the LRU cache), then
   forwards to all consumers.
5. **SigmaConsumer** wraps the event in a `sigmaEventWrapper` (which
   implements the `Select(key)` and `Keywords()` interfaces) and calls
   `ruleset.EvalAll()`. On match, it logs the alert.

---

## 4. Key Interfaces

### provider.Event (lib/provider/provider.go)

```go
type Event interface {
    ID() EventIdentifier       // {ProviderName: "LinuxEBPF", EventID: 1|3|11}
    Process() uint32           // PID
    Source() string            // "LinuxEBPF:ProcessExec" etc.
    Time() time.Time
    enrichment.DataFields      // Value(key) + ForEach(fn)
}
```

Every event in the pipeline implements this. The `enrichment.DataFields`
embedding gives access to `Value("Image")`, `Value("CommandLine")`, etc.

### provider.EventProvider (lib/provider/provider.go)

```go
type EventProvider interface {
    Name() string
    Description() string
    Initialize() error
    Close() error
    AddSource(source string) error
    SendEvents(callback func(event Event))  // blocks until Close()
    LostEvents() uint64
}
```

Currently there are two providers:
- `ebpf.Listener` -- real eBPF telemetry (Linux only)
- `replay.ReplayProvider` -- reads JSONL files (any OS, for testing)

### distributor.EventConsumer (lib/distributor/distributor.go)

```go
type EventConsumer interface {
    Name() string
    Initialize() error
    HandleEvent(event provider.Event) error
    Close() error
}
```

Currently there is one consumer: `sigma.SigmaConsumer`.

### enrichment.DataFieldsMap (lib/enrichment/enricher.go)

The central key-value store per event. It is `map[string]fmt.Stringer`.
Methods: `Value(key)`, `ForEach(fn)`, `AddField(key, value)`, `RenameField(old, new)`.

---

## 5. Event Types and Field Mappings

### Event ID 1: process_creation

**BPF hook**: `tracepoint/sched/sched_process_exec`
**Source string**: `LinuxEBPF:ProcessExec`
**Ring buffer**: `events` (8 MB default)

| Sigma Field          | Source                                        | DataFieldsMap Key      |
|----------------------|-----------------------------------------------|------------------------|
| `Image`              | `/proc/PID/exe`; fallback: BPF `filename`     | `"Image"`              |
| `CommandLine`        | `/proc/PID/cmdline` (NUL→space)               | `"CommandLine"`        |
| `ParentImage`        | Correlator cache → `/proc/PPID/exe`           | `"ParentImage"`        |
| `ParentCommandLine`  | Correlator cache → `/proc/PPID/cmdline`       | `"ParentCommandLine"`  |
| `User`               | BPF uid → `os/user.LookupId()`                | `"User"`               |
| `LogonId`            | `/proc/PID/loginuid`                          | `"LogonId"`            |
| `CurrentDirectory`   | `/proc/PID/cwd`                               | `"CurrentDirectory"`   |

Internal: `ProcessId`, `ParentProcessId`, `CommandLineTruncated`.

### Event ID 11: file_event

**BPF hooks**: `tracepoint/syscalls/sys_enter_openat` + `sys_exit_openat` (paired)
**Source string**: `LinuxEBPF:FileCreate`
**Ring buffer**: `file_events` (4 MB default)

| Sigma Field       | Source                                            | DataFieldsMap Key   |
|--------------------|--------------------------------------------------|---------------------|
| `TargetFilename`   | BPF filename + dfd, resolved to absolute path    | `"TargetFilename"`  |
| `Image`            | `/proc/PID/exe` or correlator cache              | `"Image"`           |

Internal: `User`, `ProcessId`, `FileFlags`.

**Filtering**: BPF-side checks `O_CREAT` flag. Only successful opens (ret >= 0)
are emitted. The `watched_dirs` BPF hash map allows optional path prefix filtering.

### Event ID 3: network_connection

**BPF hook**: `tracepoint/sock/inet_sock_set_state`
**Source string**: `LinuxEBPF:NetConnect`
**Ring buffer**: `net_events` (4 MB default)

| Sigma Field          | Source                                     | DataFieldsMap Key       |
|----------------------|--------------------------------------------|-------------------------|
| `Image`              | `/proc/PID/exe` or correlator cache        | `"Image"`               |
| `DestinationIp`      | BPF `daddr`, formatted IPv4/IPv6           | `"DestinationIp"`       |
| `DestinationPort`    | BPF `dport`                                | `"DestinationPort"`     |
| `Initiated`          | BPF state transition direction             | `"Initiated"`           |
| `DestinationHostname`| DNS correlation cache (NOT YET IMPLEMENTED)| `"DestinationHostname"` |

Internal: `SourceIp`, `SourcePort`, `User`, `ProcessId`, `Protocol`.

**Direction detection**: `TCP_CLOSE→TCP_SYN_SENT` = outbound (`Initiated: "true"`),
`TCP_SYN_RECV→TCP_ESTABLISHED` = inbound (`Initiated: "false"`).

---

## 6. Dependencies

| Package | Import Path | Purpose |
|---------|------------|---------|
| cilium/ebpf v0.20 | `github.com/cilium/ebpf` | Pure-Go eBPF: load BPF programs, ring buffer, maps. No CGO. |
| go-sigma-rule-engine v0.3 | `github.com/markuskont/go-sigma-rule-engine` | Sigma rule parsing and evaluation. Public, Apache-2.0. |
| logrus v1.9 | `github.com/sirupsen/logrus` | Structured logging. |
| cobra v1.10 | `github.com/spf13/cobra` | CLI framework. |
| golang-lru/v2 v2.0 | `github.com/hashicorp/golang-lru/v2` | LRU caches (correlator + user cache). |
| golang.org/x/time | `golang.org/x/time/rate` | Per-rule Sigma match throttling. |

### Important: Sigma library choice

The original plan specified `github.com/NextronSystems/go-sigma/v2`, but that
is a **private** repository. We use `github.com/markuskont/go-sigma-rule-engine`
instead. Its event interface requires two methods:

```go
Select(key string) (interface{}, bool)   // key-value field lookup
Keywords() ([]string, bool)              // unstructured keyword matching
```

These are implemented by `sigmaEventWrapper` in `sigmaconsumer.go`.

---

## 7. Build Instructions

### On macOS (development)

The project compiles on macOS using stub types (`bpf_stubs.go`, build tag
`!linux`). BPF programs won't load, but all Go code compiles and non-BPF
tests run:

```bash
go build ./...
go test ./...
go vet ./...
```

### On Linux (production)

```bash
# Prerequisites: clang, libbpf headers, bpftool (for vmlinux.h)
# Generate vmlinux.h if not present:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > lib/provider/ebpf/bpf/vmlinux.h

# Generate Go bindings from BPF C sources:
go generate ./lib/provider/ebpf/

# Build the binary:
go build -o aurora-linux ./cmd/aurora-linux/

# Run (requires root or appropriate capabilities):
sudo ./aurora-linux --rules /path/to/sigma/rules/linux/ --json
```

The `go generate` step produces `*_bpfel.go` and `*_bpfel.o` files. These
should be committed so that subsequent `go build` works without clang.

### CLI flags

```
--rules         Sigma rule directories (repeatable, required)
--logfile       Output log file path (default: stdout)
--json          JSON output format
--ringbuf-size  Ring buffer pages (default: 2048 = 8MB, currently informational)
--correlation-cache  LRU cache entries (default: 16384)
--throttle-rate      Max matches/rule/sec (default: 1.0, 0 disables throttling)
--throttle-burst     Burst per rule (default: 5, used when throttling enabled)
--verbose, -v        Debug logging
--stats-interval     Stats log interval in seconds (default: 60)
```

Startup validation fails fast with actionable errors when:
- `--rules` is missing, empty, or contains non-directory paths.
- numeric flags are out of range (e.g., non-power-of-two `--ringbuf-size`).
- `--logfile` points to a path whose parent directory does not exist.

---

## 8. Testing

### Current tests (all pass on macOS)

| Test file | What it covers |
|-----------|---------------|
| `lib/provider/ebpf/fieldmap_test.go` | `joinCmdline` (NUL→space, truncation), `nullTermStr`, `buildExecFieldsMap`, `buildFileFieldsMap`, `buildNetFieldsMap`, `formatIPv4` |
| `lib/provider/ebpf/listener_test.go` | Partial-init behavior (disable failed monitors, fail when all fail) |
| `lib/provider/replay/replay_test.go` | Source filtering, numeric parsing, large-line handling, close semantics, concurrent AddSource+SendEvents |
| `lib/distributor/distributor_test.go` | Consumer snapshot behavior; registration not blocked by in-flight callback |
| `lib/distributor/enrichments_test.go` | Invalid PID handling in enrichment functions |
| `lib/enrichment/enricher_test.go` | `DataFieldsMap.Value`, `ForEach`, `RenameField`, `EventEnricher.Register`+`Enrich` |
| `lib/enrichment/correlator_test.go` | `Correlator.Store`+`Lookup`, cache miss, LRU eviction |
| `lib/consumer/sigma/sigmaconsumer_test.go` | Throttle behavior, invalid-rule-dir behavior, field collision handling, redaction, rule-level lookup benchmark |
| `lib/logging/textformatter_test.go` | Text formatter escaping of keys/values to prevent log injection |
| `cmd/aurora-linux/agent/*_test.go` | Startup validation + secure logfile open/close behavior |

### Integration tests (NOT YET WRITTEN, require Linux + root)

These should be tagged `//go:build integration` and:

1. Load the real BPF programs via `Listener.Initialize()`.
2. Execute test commands (`/bin/echo sigma-test-marker`).
3. Assert that the expected events appear with correct field values.
4. Wire a Sigma rule through the full pipeline and assert a match.

### Replay-based CI tests (NOT YET WRITTEN)

Use `lib/provider/replay/replay.go` to feed recorded JSONL events through
the pipeline without needing BPF. The JSONL fixture file
(`testdata/recorded_exec_events.jsonl`) needs to be recorded from a real
Linux test run.

---

## 9. Design Decisions and Rationale

### Why eBPF and not auditd/syslog?

- eBPF fires at the exact kernel hook point with nanosecond precision.
- No log parsing, no regex, no ambiguity about field format.
- Much lower overhead than auditd (which writes to disk first).
- Ring buffer transport avoids the kernel log bottleneck entirely.

### Why read /proc in userland instead of capturing everything in BPF?

- BPF stack is 512 bytes. Capturing variable-length argv requires
  multiple `bpf_probe_read_user()` calls and truncation is inevitable.
- `/proc/PID/cmdline` is the canonical, complete source.
- Keeping BPF programs small reduces verifier complexity.
- The BPF program captures only what's needed to **identify** the event
  (pid, ppid, uid, filename). Richer fields are reconstructed in userland.

### Why BPF ring buffer and not perf buffer?

- Ring buffer is globally ordered (critical for parent→child correlation).
- Memory-efficient: single shared buffer vs per-CPU waste.
- Variable-size reserve/commit vs fixed-size padding.
- The code falls back to perf buffer for kernels 5.2-5.7.

### Why markuskont/go-sigma-rule-engine and not NextronSystems/go-sigma/v2?

- go-sigma/v2 is **private** -- cannot be used as a public dependency.
- go-sigma-rule-engine is public (Apache-2.0), actively maintained.
- Its API is different: `Select(key)` + `Keywords()` instead of `GetField(key)`.

### Why correlator caches process data in two places?

The listener stores process data in the correlator during `parseExecEvent()`,
AND the distributor stores it during `cacheProcessData()`. This is intentional
redundancy -- the listener stores it immediately so that very rapid child
processes can find their parent, while the distributor stores it after
enrichment so the cached data includes any enricher modifications. The LRU
nature means the second write just updates the same key.

### Log source YAML files

`resources/log-sources/` contains config files that map Sigma rule categories
to provider source strings. These follow the same schema as the Windows Aurora
agent's ETW log source files. They are NOT currently wired into the
`go-sigma-rule-engine` (which loads rules directly from directories without
log source routing). This is a gap -- see "What needs work" below.

---

## 10. What Currently Works

- Full project compiles (`go build ./...`, `go vet ./...`).
- All unit tests pass (`go test ./...`).
- BPF C programs are written for all 3 event types.
- The Go Listener correctly parses all 3 event binary structs.
- Field reconstruction from /proc is complete for all fields.
- Parent process correlation via LRU cache is implemented.
- Sigma consumer loads rules, evaluates events, throttles matches.
- CLI validates user input and fails fast with actionable errors.
- CLI with cobra is functional with examples and required `--rules`.
- systemd service file is ready.
- Replay provider exists for testing without BPF.
- JSON and text log formatters work; text output escapes untrusted fields.

---

## 11. What Needs Work (Ordered by Priority)

### P0: Generate BPF objects on Linux

The BPF C programs exist but `go generate` has not been run on a Linux host.
You need:
1. A Linux machine (kernel 5.8+) with `clang`, `llvm`, `libbpf-dev`.
2. Generate `vmlinux.h`: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > lib/provider/ebpf/bpf/vmlinux.h`
3. Run: `go generate ./lib/provider/ebpf/`
4. Commit the generated `*_bpfel.go` + `*_bpfel.o` files.
5. Remove or gate `bpf_stubs.go` behind `//go:build !linux` (already done).

### P1: Log source routing

The `go-sigma-rule-engine` library loads ALL rules from a directory and
evaluates ALL of them against every event. There is no log source routing
-- a `process_creation` rule would be evaluated against `file_event` events
(and just not match). This works but is inefficient.

To fix this, the Sigma consumer should:
- Parse the `logsource` section of each rule at load time.
- Group rules by `{category, product}`.
- In `HandleEvent()`, only evaluate rules matching the event's category
  (determined by EventID: 1=process_creation, 11=file_event, 3=network_connection).

The `resources/log-sources/*.yml` files define these mappings but are not
yet used by the code.

### P2: DestinationHostname via DNS correlation

3 of the 5 network_connection Sigma rules require `DestinationHostname`
(crypto mining pools, ngrok tunnels, localtonet). This field is currently
always empty.

Implementation plan (from `docs/plan_aurora_linux_ebpf_sigma.md` Section 5.9):
- Add BPF programs on `kprobe/udp_sendmsg` (dport=53) and `kprobe/udp_recvmsg` (sport=53).
- Parse DNS query/response in userland.
- Populate an IP→hostname LRU cache (65,536 entries, 300s TTL).
- In the network event enricher, look up `daddr` in this cache.

### P3: Integration tests

Write `lib/provider/ebpf/integration_test.go` with `//go:build integration`:
- Test that executing `/bin/echo test-marker` produces an event with correct fields.
- Test end-to-end Sigma match with a minimal test rule.

### P4: Replay test fixture

Record events from a real Linux test run to `testdata/recorded_exec_events.jsonl`,
then write a CI test that loads these through the replay provider and asserts
expected Sigma matches.

### P5: Ring buffer size configurability

The `--ringbuf-size` CLI flag exists but is not actually passed to the BPF
programs. The ring buffer sizes are hardcoded in the C sources (`8 * 1024 * 1024`
for exec, `4 * 1024 * 1024` for file/net). To make this configurable, the
listener would need to use `cilium/ebpf.CollectionOptions` to override map
sizes at load time. The current CLI/help text marks this flag as informational
to reduce operator confusion.

### P6: File event watched_dirs population

The `watched_dirs` BPF hash map in `file_monitor.c` exists but is not
populated from userland. The listener should write the default watched
prefixes (`/etc/`, `/tmp/`, `/var/tmp/`, `/var/spool/`, `/root/`, `/home/`)
into this map during `initFile()`.

### P7: Process termination tracking

Currently the correlator cache only grows (LRU evicts old entries). Adding a
`sched_process_exit` tracepoint would allow explicit cache cleanup and enable
`process_termination` events for lifetime analysis.

### P8: Graceful enrichment on process exit race

If a process exits before the listener reads `/proc/PID/exe`, the read fails
and the BPF `filename` is used as fallback. This is rare (the tracepoint fires
before the first timeslice) but under extreme load it can happen. The code
handles this gracefully but could be improved by reading more fields in the
BPF program itself (at the cost of BPF complexity).

---

## 12. Code Conventions

- **Go version**: 1.24+ (as specified in go.mod).
- **Package naming**: lowercase, single-word where possible.
- **Error handling**: Always wrap with `fmt.Errorf("context: %w", err)`.
- **Logging**: Use `logrus` throughout. Field-based logging, not string interpolation.
- **Build tags**: `//go:build !linux` for non-Linux stubs, `//go:build integration` for tests requiring root + BPF.
- **BPF C code**: SPDX license header, `//go:build ignore` to prevent Go from compiling `.c` files, SEC annotations for bpf2go.
- **Field names**: Match Sigma field names exactly (PascalCase: `Image`, `CommandLine`, `TargetFilename`, `DestinationIp`).

---

## 13. Related Files Outside This Repo

These are in sibling directories and were used during design:

- `/Users/neo/code/Workspace/sigma/rules/linux/` -- Source of truth for
  Sigma field names. Contains `process_creation/` (119 rules),
  `file_event/` (8 rules), `network_connection/` (5 rules).
- `/Users/neo/code/Workspace/aurora-agent-manual/` -- Windows Aurora agent
  manual (reference for architecture patterns, not code-shared).
- `/Users/neo/code/Workspace/aurora/` -- Windows Aurora codebase. **Do NOT
  modify or import from this repo.**
