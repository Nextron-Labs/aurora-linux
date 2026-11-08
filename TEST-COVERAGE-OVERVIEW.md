# Aurora Linux — Test Coverage Overview

Last updated: 2026-03-14

## Summary

| Component | Source Lines | Test Lines | Coverage Rating |
|-----------|-------------|------------|-----------------|
| **cmd/aurora/agent** (config, validate, params, output) | 1,162 | ~880 | 🟢 Good |
| **cmd/aurora** (main CLI) | 184 | 124 | 🟢 Good |
| **cmd/aurora-util** (maintenance CLI) | 1,121 | 275 | 🟡 Medium |
| **lib/consumer/sigma** (Sigma engine + match evidence) | 1,100 | ~820 | 🟢 Good |
| **lib/consumer/ioc** (IOC matching) | 517 | ~600 | 🟢 Good |
| **lib/distributor** (event routing + integration) | 220 | ~550 | 🟢 Good |
| **lib/enrichment** (correlator + enricher) | 149 | 169 | 🟢 Good |
| **lib/logging** (formatters) | 195 | ~320 | 🟢 Good |
| **lib/provider/ebpf** (eBPF listener) | 1,193 | 369 | 🔴 Low |
| **lib/provider/replay** (JSONL replay) | 251 | 160 | 🟢 Good |

---

## What's Covered (completed)

### Phase 1 — Output Sinks + Pipeline Integration ✅
- `networkWriter` (TCP/UDP connect, write, reconnect, close idempotency, lazy connect)
- `formattedOutputHook` (logrus hook → writer, nil safety, Levels())
- `resolveOutputFormat` / `formatterForOutputFormat`
- End-to-end pipeline: Replay → Distributor → Sigma + IOC consumers
- Parent process enrichment from correlator cache
- Clean events producing zero false positives

### Phase 2 — Match Evidence + IOC Edge Cases ✅
- `parseFieldSelector`, `extractDetectionFieldPatterns`, `formatMatchEvidence`
- `uniqueStrings`, `textPatternFromModifiers`, `selectionStringValue/IntValue`
- `ruleLookupKey`, `ruleMetadata.matchingRulePatterns`, `newRuleFieldPattern`
- `stringifyRuleMetadataValue`
- IOC: `sanitizeFieldForLogging` (key redaction + command-line secrets)
- IOC: `logLevelForFilenameScore`, `isLikelyDomain`, `normalizeIP`, `normalizeDomain`
- IOC: `loadFilenameIOCs` (dedup, malformed lines), `loadC2IOCs` (categorization)
- IOC: Multiple IOC matches on single event

### Phase 3 — Throttle + Formatters ✅
- Sigma throttle: per-rule isolation, burst size, default burst fallback
- JSON formatter: full test coverage (timestamp, empty message, special chars, all levels)
- Syslog formatter: severity mapping, facility validation, hostname fallback, app name, field sorting
- Text formatter: basic format, default timestamp, empty message, field sorting, numeric values

---

## Remaining Gaps

### eBPF Package (blocked by `go generate`)
- **`procfs.go`** (97L) — reads `/proc/PID/{exe,cmdline,cwd,loginuid}` — zero tests
- **`usercache.go`** (40L) — UID→username lookup with caching — zero tests
- **`event.go`** (61L) — event type definitions — zero tests

These require the eBPF generated code (`go generate ./lib/provider/ebpf/`) which needs bpftool/clang on Linux.

### Minor Gaps (nice to have)
- `validateHostPort` with port 0 and port 65536
- `isLoopbackHost` with `[::1]` (bracketed IPv6)
- Enricher with multiple manipulators for same key
- Correlator with `NewCorrelator(0)` (zero-size)
- Malformed JSON lines in replay (assertion on skip count)

---

## How to Run Tests

```bash
cd ~/clawd/projects/aurora-linux

# All compilable packages
go test ./lib/...

# With race detector
go test -race ./lib/...

# Coverage report
go test -coverprofile=coverage.out ./lib/...
go tool cover -func=coverage.out
```
