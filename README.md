# Aurora Linux

Aurora Linux is a real-time Linux EDR agent.

It attaches eBPF programs to kernel tracepoints, enriches the captured telemetry in user space, and evaluates each event against Sigma rules to emit high-signal alerts in text or JSON. The goal is practical host detection with low overhead and clear, actionable output.

```mermaid
flowchart LR
  subgraph KERNEL["Kernel"]
    E1["sched_process_exec"]
    E2["sys_enter/sys_exit_openat"]
    E3["inet_sock_set_state"]
  end

  subgraph USER["User Space"]
    L["eBPF Listener"]
    C["Enrichment + Correlation"]
    S["Sigma Engine"]
  end

  E1 --> L
  E2 --> L
  E3 --> L
  L -->|ring buffers| C
  C -->|LRU parent cache| S
  S -->|JSON/text alerts| A["Alert Output"]
```

## What It Detects

Aurora Linux loads standard [Sigma rules](https://github.com/SigmaHQ/sigma) for Linux and matches them in real time against three event types:

| Event Type | eBPF Hook | Example Detections |
|---|---|---|
| **Process Creation** | `tracepoint/sched/sched_process_exec` | Reverse shells, base64 decode, webshell child processes, suspicious Java children |
| **File Creation** | `tracepoint/syscalls/sys_{enter,exit}_openat` | Cron persistence, sudoers modification, rootkit lock files, downloads to /tmp |
| **Network Connection** | `tracepoint/sock/inet_sock_set_state` | Bash reverse shells, malware callback ports, C2 on non-standard ports |

## Requirements

- Linux kernel **5.8+** (recommended; 5.2+ with degraded support)
- Root privileges (or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE`)
- Go 1.24+ (build only)
- clang + libbpf headers (BPF compilation only)

## Quick Start

### Build

```bash
# On a Linux host with clang and bpftool installed:

# 1. Generate vmlinux.h (one-time)
bpftool btf dump file /sys/kernel/btf/vmlinux format c \
    > lib/provider/ebpf/bpf/vmlinux.h

# 2. Compile BPF C programs → Go bindings
go generate ./lib/provider/ebpf/

# 3. Build the binary
go build -o aurora-linux ./cmd/aurora-linux/
```

### Run

```bash
# Point at one or more Sigma rules directories and run
sudo ./aurora-linux \
    --rules /path/to/sigma/rules/linux/process_creation/ \
    --rules /path/to/sigma/rules/linux/file_event/ \
    --rules /path/to/sigma/rules/linux/network_connection/ \
    --json
```

`--rules` is required. Aurora validates rule directories at startup and exits
with an actionable error if the paths are missing or invalid.

### Deploy as a Service

```bash
sudo cp aurora-linux /opt/aurora-linux/
sudo cp deploy/aurora-linux.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aurora-linux
```

## Example Output

When a Sigma rule matches, Aurora Linux emits a structured alert:

```json
{
  "level": "warning",
  "message": "Sigma match",
  "sigma_rule": "e2072cab-8c9a-459b-b63c-40ae79e27031",
  "sigma_title": "Decode Base64 Encoded Text",
  "sigma_level": "low",
  "Image": "/usr/bin/base64",
  "CommandLine": "base64 -d /tmp/encoded_payload.b64",
  "ParentImage": "/bin/bash",
  "User": "root",
  "ProcessId": "8421",
  "timestamp": "2026-02-11T12:00:00.000000000Z"
}
```

## Configuration

| Flag | Default | Description |
|---|---|---|
| `--rules` | (required) | Sigma rule directories (repeatable) |
| `--logfile` | stdout | Output log file path |
| `--json` | off | JSON output format |
| `--ringbuf-size` | 2048 | Ring buffer size in pages (currently informational; runtime tuning planned) |
| `--correlation-cache` | 16384 | Parent process LRU cache entries |
| `--throttle-rate` | 1.0 | Max Sigma matches per rule per second (`0` disables throttling) |
| `--throttle-burst` | 5 | Burst allowance per rule (used when throttling is enabled) |
| `--stats-interval` | 60 | Stats logging interval (seconds, 0=off) |
| `-v, --verbose` | off | Debug-level logging |

Operational notes:
- If `--logfile` is set and cannot be opened safely, startup fails instead of silently falling back to stdout.
- Text and JSON alert logs preserve reserved Sigma metadata fields and redact common secret/token patterns in logged fields.

## Architecture

Aurora Linux follows a **provider → distributor → consumer** pipeline:

- **Provider** (`lib/provider/ebpf/`) -- eBPF programs attach to kernel tracepoints and deliver events via ring buffers. A userland listener reconstructs full fields from `/proc/PID/*`.
- **Distributor** (`lib/distributor/`) -- Applies enrichment functions (parent process correlation via LRU cache, UID→username resolution) and routes events to consumers.
- **Consumer** (`lib/consumer/sigma/`) -- Evaluates events against loaded Sigma rules using [go-sigma-rule-engine](https://github.com/markuskont/go-sigma-rule-engine). Includes per-rule throttling to suppress duplicate alerts.

### Sigma Field Coverage

| Category | Sigma Fields Covered | Rule Coverage |
|---|---|---|
| `process_creation` | Image, CommandLine, ParentImage, ParentCommandLine, User, LogonId, CurrentDirectory | 119/119 rules (100%) |
| `file_event` | TargetFilename, Image | 8/8 rules (100%) |
| `network_connection` | Image, DestinationIp, DestinationPort, Initiated | 2/5 rules (40%) -- remaining 3 need DNS correlation |

## Project Structure

```
aurora-linux/
├── cmd/aurora-linux/          CLI entry point (cobra)
├── lib/
│   ├── provider/ebpf/         eBPF listener + BPF C programs
│   ├── provider/replay/       JSONL replay provider (for CI)
│   ├── distributor/           Event routing + enrichment
│   ├── enrichment/            DataFieldsMap, correlator cache
│   ├── consumer/sigma/        Sigma rule evaluation
│   └── logging/               JSON + text formatters
├── resources/log-sources/     Legacy Sigma category→provider mapping files (not currently consumed by runtime)
├── deploy/                    systemd unit file
└── docs/                      Design plan + developer guide
```

## Documentation

- **[Developer Guide](docs/DEVELOPER.md)** -- Codebase walkthrough, design decisions, what works, what needs work. Start here if you're contributing.
- **[Technical Design Plan](docs/plan_aurora_linux_ebpf_sigma.md)** -- Full technical specification with BPF struct definitions, field mapping tables, worked examples, and performance analysis.

## Development

```bash
# Build (compiles on macOS via stubs, runs on Linux only)
go build ./...

# Run tests (field mapping, enrichment, correlator)
go test ./...

# Lint
go vet ./...
```

## License

GPL-3.0. See [LICENSE](LICENSE).
