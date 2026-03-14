# Aurora Linux — Test Coverage Overview

Generated: 2026-03-14

## Summary

| Component | Source Lines | Test Lines | Test Functions | Coverage Rating |
|-----------|-------------|------------|----------------|-----------------|
| **cmd/aurora/agent** (agent, config, validate, params, output, format) | 1,162 | 603 | 25 | 🟡 Medium |
| **cmd/aurora** (main CLI) | 184 | 124 | 4 | 🟢 Good |
| **cmd/aurora-util** (maintenance CLI) | 1,121 | 275 | — | 🟡 Medium |
| **lib/consumer/sigma** (Sigma engine) | 1,100 | 389 | 10 | 🟡 Medium |
| **lib/consumer/ioc** (IOC matching) | 517 | 227 | 4 | 🟡 Medium |
| **lib/distributor** (event routing) | 220 | 144 | 4 | 🟢 Good |
| **lib/enrichment** (correlator + enricher) | 149 | 169 | 8 | 🟢 Good |
| **lib/logging** (formatters) | 195 | 106 | 4 | 🟡 Medium |
| **lib/provider/ebpf** (eBPF listener) | 1,193 | 369 | — | 🔴 Low |
| **lib/provider/replay** (JSONL replay) | 251 | 160 | 5 | 🟢 Good |
| **TOTAL** | **6,292** | **2,566** | — | — |

---

## Critical Gaps (Priority 1 — should fix first)

### 1. Output Sinks: Zero Tests
**File:** `cmd/aurora/agent/output_sinks.go` (132 lines)  
**Risk:** HIGH — these deliver alerts to external systems

No tests for:
- `formattedOutputHook` (logrus hook that writes to file/network)
- `networkWriter` (TCP/UDP client with lazy connect + retry)
- `writeAllWithDeadline` (deadline-based write loop)
- Reconnect-on-failure behavior (the retry path in `Write`)
- `Close()` idempotency on `networkWriter`

**Impact:** A bug here means silent alert loss in production. TCP reconnect logic is particularly tricky and untested.

### 2. eBPF Field Mapping: Only fieldmap_test covers unit logic
**Files:** `fieldmap.go` (124L), `procfs.go` (97L), `usercache.go` (40L), `event.go` (61L)  
**Risk:** HIGH — field mapping errors cause missed Sigma detections

`fieldmap_test.go` (313L) covers `joinCmdline` and the field builder functions well, but:
- **`procfs.go`** (97L) — reads `/proc/PID/{exe,cmdline,cwd,loginuid}` — **zero tests**
- **`usercache.go`** (40L) — UID→username lookup with caching — **zero tests**
- **`event.go`** (61L) — event type definitions and `Source()` method — **zero tests**

**Impact:** procfs parsing failures silently produce empty fields, breaking detection.

### 3. Distributor Pipeline Integration: No end-to-end test
**Risk:** MEDIUM-HIGH — the core event flow is untested as a whole

No test exercises: Provider → Distributor (enrichment) → Sigma Consumer + IOC Consumer together. The existing distributor test only verifies concurrent registration, not actual event routing through enrichment to consumers producing matches.

### 4. matchdetails.go: 660 lines with zero dedicated tests
**File:** `lib/consumer/sigma/matchdetails.go`  
**Risk:** MEDIUM-HIGH — match evidence is what analysts act on

Tested indirectly via `TestHandleEventIncludesRuleMetadataAndMatchEvidence`, but no unit tests for:
- `extractDetectionFieldPatterns` (YAML detection → field pattern extraction)
- `evalBranchForEvidence` (recursive AST walk with AND/OR/NOT)
- `collectSelectionEvidence` (pattern-level evidence from selections)
- `formatMatchEvidence` (output formatting)
- `readRuleDateMetadata` (YAML date parsing edge cases)
- `parseFieldSelector` (e.g. `Image|endswith` → field + modifiers)
- Edge cases: deeply nested conditions, multiple OR branches, NOT negation

---

## Important Gaps (Priority 2)

### 5. IOC Consumer: Missing edge case tests
**File:** `lib/consumer/ioc/iocconsumer.go`  
**Existing:** 4 test functions (227L) — good basics

Missing:
- `sanitizeFieldForLogging` — credential redaction (password, token, API key in field names)
- `logLevelForFilenameScore` — score 60-79 → warn, <60 → info
- Multiple filename IOC matches on a single event
- Duplicate IOC entry dedup (`seen` map in `loadFilenameIOCs`)
- `isLikelyDomain` edge cases: `..evil.com`, `.evil.com`, `evil.com.`, unicode domains
- `normalizeIP` with IPv6 addresses
- Default IOC path resolution (`resolveIOCPaths`)
- Large IOC file handling

### 6. Sigma Throttle: Only burst limit tested
**File:** `lib/consumer/sigma/sigmaconsumer.go`  
**Existing:** `TestAllowMatchDisabledThrottleAllowsAll`, `TestAllowMatchEnabledThrottleLimitsBurst`

Missing:
- Throttle recovery after time passes (token refill)
- Per-rule isolation (rule-A throttled, rule-B still fires)
- `HandleEvent` integration with throttle (match emitted vs suppressed)

### 7. Logging Formatters: Thin coverage
**Files:** `jsonformatter.go` (41L), `syslogformatter.go` (87L), `textformatter.go` (67L)  
**Existing:** 4 tests across 3 files

Missing:
- `JSONFormatter`: timestamp format override, empty message, special characters in values
- `SyslogFormatter`: facility range validation, hostname fallback to `os.Hostname()`, severity mapping for all log levels
- `TextFormatter`: only escaping tested, not basic format structure

### 8. Config File Merge: Partial field coverage
**File:** `cmd/aurora/agent/config.go` (131L)  
**Existing:** 2 tests

Missing:
- Empty YAML file (should be valid, no changes)
- Partial config (only some fields set, others keep defaults)
- Missing file error
- Nil `params` pointer

---

## Adequate Coverage (Priority 3 — nice to extend)

### 9. Validation: Good but incomplete
**File:** `cmd/aurora/agent/validate.go` (174L)  
**Existing:** 16 test functions — solid

Minor gaps:
- `validateHostPort` with port 0 and port 65536
- `isLoopbackHost` with `[::1]` (bracketed IPv6)
- Empty string in `RuleDirs` slice

### 10. Enrichment + Correlator: Good
**Files:** `enricher.go` (101L), `correlator.go` (48L)  
**Existing:** 8 tests — well covered

Minor gaps:
- Enricher with multiple manipulators for same key
- Correlator with `NewCorrelator(0)` (zero-size)

### 11. Replay Provider: Good
**File:** `lib/provider/replay/replay.go` (251L)  
**Existing:** 5 tests — solid

Minor gaps:
- Malformed JSON lines (tested implicitly, but no assertion on skip count)
- Empty JSONL file
- Missing `_provider` field defaults

---

## Recommended Test Plan — Priority Order

### Phase 1: Critical (output sinks + pipeline integration)

| # | What to Test | New File | Est. Lines |
|---|-------------|----------|------------|
| 1 | `networkWriter` (TCP/UDP connect, write, retry, close) | `agent/output_sinks_test.go` | ~200 |
| 2 | `formattedOutputHook` (logrus hook → writer) | `agent/output_sinks_test.go` | ~80 |
| 3 | Pipeline integration: replay → distributor → sigma+IOC | `distributor/integration_test.go` | ~250 |

### Phase 2: Detection correctness (matchdetails + IOC edge cases)

| # | What to Test | New File | Est. Lines |
|---|-------------|----------|------------|
| 4 | `parseFieldSelector`, `extractDetectionFieldPatterns` | `sigma/matchdetails_test.go` | ~150 |
| 5 | `evalBranchForEvidence` with AND/OR/NOT trees | `sigma/matchdetails_test.go` | ~200 |
| 6 | `formatMatchEvidence` output structure | `sigma/matchdetails_test.go` | ~80 |
| 7 | IOC `sanitizeFieldForLogging`, score levels, domain validation | `ioc/iocconsumer_test.go` (extend) | ~150 |

### Phase 3: Robustness (procfs, throttle, formatters)

| # | What to Test | New File | Est. Lines |
|---|-------------|----------|------------|
| 8 | `procfs.go` parsers (mockable via temp files) | `ebpf/procfs_test.go` | ~120 |
| 9 | `usercache.go` UID resolution | `ebpf/usercache_test.go` | ~60 |
| 10 | Throttle token refill + per-rule isolation | `sigma/sigmaconsumer_test.go` (extend) | ~80 |
| 11 | Formatter edge cases | `logging/*_test.go` (extend) | ~100 |

**Total estimated new test code: ~1,470 lines**

---

## How to Run Tests

```bash
cd ~/clawd/projects/aurora-linux

# All tests
go test ./...

# Specific package
go test ./lib/consumer/sigma/ -v

# With race detector
go test -race ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```
