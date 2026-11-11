package syslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// Real-world examples from the user's brief: kernel-level warnings
// emitted by CVE-2026-31431 (Copy Fail) shellcode that calls execve with
// a NULL argv on Debian-based hosts.
const sampleSyslog = `2026-04-30T03:16:46.845745+00:00 ip-172-31-40-101 kernel: process 'su' launched '/bin/sh' with NULL argv: empty string added
2026-04-30T07:53:51.233087+00:00 ip-172-31-40-101 kernel: process 'passwd' launched '/bin/sh' with NULL argv: empty string added
`

// ---------------------------------------------------------------------------
// Parser-level tests
// ---------------------------------------------------------------------------

func TestParseLineISO(t *testing.T) {
	line := `2026-04-30T03:16:46.845745+00:00 ip-172-31-40-101 kernel: process 'su' launched '/bin/sh' with NULL argv: empty string added`

	parsed := parseLine(line)
	if parsed == nil {
		t.Fatal("parseLine returned nil")
	}
	if parsed.Host != "ip-172-31-40-101" {
		t.Errorf("Host = %q, want ip-172-31-40-101", parsed.Host)
	}
	if parsed.Program != "kernel" {
		t.Errorf("Program = %q, want kernel", parsed.Program)
	}
	if parsed.PID != 0 {
		t.Errorf("PID = %d, want 0", parsed.PID)
	}
	wantMsg := "process 'su' launched '/bin/sh' with NULL argv: empty string added"
	if parsed.Message != wantMsg {
		t.Errorf("Message = %q, want %q", parsed.Message, wantMsg)
	}

	wantTS := time.Date(2026, 4, 30, 3, 16, 46, 845745000, time.UTC)
	if !parsed.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v", parsed.Timestamp.UTC(), wantTS)
	}
}

func TestParseLineRFC3164(t *testing.T) {
	line := `Apr 30 03:16:46 host01 sshd[1234]: Accepted password for root from 10.0.0.1 port 22 ssh2`

	parsed := parseLine(line)
	if parsed == nil {
		t.Fatal("parseLine returned nil")
	}
	if parsed.Host != "host01" {
		t.Errorf("Host = %q, want host01", parsed.Host)
	}
	if parsed.Program != "sshd" {
		t.Errorf("Program = %q, want sshd", parsed.Program)
	}
	if parsed.PID != 1234 {
		t.Errorf("PID = %d, want 1234", parsed.PID)
	}
	if !strings.HasPrefix(parsed.Message, "Accepted password") {
		t.Errorf("Message = %q, want prefix 'Accepted password'", parsed.Message)
	}
}

func TestParseLineWithRFC5424PRI(t *testing.T) {
	line := `<13>1 2026-04-30T03:16:46.845745+00:00 ip-172-31-40-101 kernel: process 'su' launched '/bin/sh' with NULL argv: empty string added`

	parsed := parseLine(line)
	if parsed == nil {
		t.Fatal("parseLine returned nil")
	}
	if parsed.Program != "kernel" {
		t.Fatalf("Program = %q, want kernel", parsed.Program)
	}
}

func TestParseLineEmpty(t *testing.T) {
	if parseLine("") != nil {
		t.Error("parseLine(\"\") should return nil")
	}
	if parseLine("\n") != nil {
		t.Error("parseLine(\"\\n\") should return nil")
	}
}

func TestParseLineGarbageStillReturnsRawAsMessage(t *testing.T) {
	line := "this is not a syslog line"
	parsed := parseLine(line)
	if parsed == nil {
		t.Fatal("parseLine(garbage) returned nil; expected fallback")
	}
	if parsed.Raw != line {
		t.Errorf("Raw = %q, want %q", parsed.Raw, line)
	}
	if parsed.Message != line {
		t.Errorf("Message = %q, want %q", parsed.Message, line)
	}
}

// ---------------------------------------------------------------------------
// Provider-level tests (file source)
// ---------------------------------------------------------------------------

// TestFullProviderFromFile reads the sample log and verifies that two
// well-formed events with the expected fields are emitted.
func TestFullProviderFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "syslog")
	if err := os.WriteFile(logFile, []byte(sampleSyslog), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewFromFiles(logFile)
	p.SetFollow(false) // drain to EOF in tests
	_ = p.AddSource(SourceSyslog)
	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	var events []provider.Event
	p.SendEvents(func(event provider.Event) {
		events = append(events, event)
	})

	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}

	first := events[0]
	if first.ID().ProviderName != ProviderName {
		t.Errorf("event[0] ProviderName = %q, want %q", first.ID().ProviderName, ProviderName)
	}
	if first.Source() != SourceSyslog {
		t.Errorf("event[0] Source = %q, want %q", first.Source(), SourceSyslog)
	}
	if v := first.Value("program"); v.String != "kernel" {
		t.Errorf("event[0] program = %q, want kernel", v.String)
	}
	if v := first.Value("host"); v.String != "ip-172-31-40-101" {
		t.Errorf("event[0] host = %q, want ip-172-31-40-101", v.String)
	}
	if v := first.Value("type"); v.String != "syslog" {
		t.Errorf("event[0] type = %q, want syslog", v.String)
	}
	wantMsg := "process 'su' launched '/bin/sh' with NULL argv: empty string added"
	if v := first.Value("message"); v.String != wantMsg {
		t.Errorf("event[0] message = %q, want %q", v.String, wantMsg)
	}

	second := events[1]
	if v := second.Value("message"); !strings.Contains(v.String, "process 'passwd'") {
		t.Errorf("event[1] message = %q, want to contain 'process 'passwd''", v.String)
	}
}

// TestInitializeFailsWhenNoSourceReadable verifies the requested behaviour
// of "raise an alert if it is not possible to read syslog": the provider
// must fail to initialize when nothing is reachable.
func TestInitializeFailsWhenNoSourceReadable(t *testing.T) {
	p := NewFromFiles("/this/path/does/not/exist", "/another/missing.log")
	p.SetFollow(false)
	err := p.Initialize()
	if err == nil {
		t.Fatal("Initialize() with no readable files should return an error")
	}
	if !strings.Contains(err.Error(), "unable to read") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestInitializeKeepsReadableSubset verifies that mixing readable and
// unreadable paths drops the bad ones and keeps the good ones (so a host
// with /var/log/messages but missing /var/log/syslog still works).
func TestInitializeKeepsReadableSubset(t *testing.T) {
	tmpDir := t.TempDir()
	good := filepath.Join(tmpDir, "messages")
	if err := os.WriteFile(good, []byte("Apr 30 03:16:46 host kernel: hello\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewFromFiles("/this/does/not/exist", good)
	p.SetFollow(false)
	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v (expected success because one file is readable)", err)
	}
	files := p.Files()
	if len(files) != 1 || files[0] != good {
		t.Fatalf("Files = %v, want [%s]", files, good)
	}
}

// TestInitializeFailsWithNoSourcesConfigured verifies that constructing
// a provider with neither files nor journald is rejected.
func TestInitializeFailsWithNoSourcesConfigured(t *testing.T) {
	p := New(Config{})
	if err := p.Initialize(); err == nil {
		t.Fatal("Initialize() expected error when no sources configured")
	}
}

// TestSourceFilteringSkipsDisabledEvents verifies that the source
// allow-list (used by AddSource) does in fact gate events.
func TestSourceFilteringSkipsDisabledEvents(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "syslog")
	if err := os.WriteFile(logFile, []byte(sampleSyslog), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewFromFiles(logFile)
	p.SetFollow(false)
	// Only allow journald — file events should be filtered out.
	_ = p.AddSource(SourceJournald)
	if err := p.Initialize(); err != nil {
		t.Fatal(err)
	}
	count := 0
	p.SendEvents(func(event provider.Event) { count++ })
	if count != 0 {
		t.Errorf("got %d events, want 0 when source is filtered out", count)
	}
}

// ---------------------------------------------------------------------------
// Sigma rule end-to-end test
// ---------------------------------------------------------------------------

// copyFailSigmaRule is the CVE-2026-31431 (Copy Fail) rule from the
// brief. The condition is `all of them` rather than `all of keywords_*`
// because go-sigma-rule-engine v0.3.0 (the engine vendored by this
// project) routes wildcard idents through the selection branch builder,
// which rejects list-of-strings keyword blocks. With only the three
// keyword groups in this rule, `all of them` is logically identical and
// is recognised correctly as a keyword detection.
const copyFailSigmaRule = `title: CVE-2026-31431 Copy Fail - Setuid Binary NULL Argv Shell Execution
id: a1f4c2d7-83b5-4e90-9c12-7d3e5a8b1f06
status: experimental
description: |
    Detects the kernel-level warning emitted when shellcode injected into a setuid-root binary's page cache by the CVE-2026-31431 (Copy Fail) exploit calls execve with a NULL argv.
references:
    - https://xint.io/blog/copy-fail-linux-distributions
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-04-30
tags:
    - attack.privilege-escalation
    - cve.2026-31431
logsource:
    product: linux
    service: syslog
detection:
    keywords_process:
        - "process 'su'"
        - "process 'sudo'"
        - "process 'passwd'"
        - "process 'mount'"
        - "process 'newgrp'"
        - "process 'gpasswd'"
        - "process 'chfn'"
    keywords_pattern:
        - "with NULL argv"
    keywords_child_process:
        - "launched '/bin/sh'"
        - "launched '/bin/bash'"
        - "launched '/bin/zsh'"
        - "launched '/bin/ksh'"
        - "launched '/bin/dash'"
        - "launched '/bin/ash'"
        - "launched '/bin/tcsh'"
        - "launched '/bin/csh'"
        - "launched '/bin/fish'"
    condition: all of them
falsepositives:
    - Unlikely
level: high
`
