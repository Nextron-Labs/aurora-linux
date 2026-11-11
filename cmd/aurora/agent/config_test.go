package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyConfigFileSetsSupportedFields(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "aurora.yml")
	cfg := `
rules:
  - /tmp/rules/linux
audit-log:
  - " /var/log/audit/audit.log "
filename-iocs: /tmp/filename-iocs.txt
c2-iocs: /tmp/c2-iocs.txt
logfile: /tmp/aurora.log
logfile-format: syslog
json: true
low-prio: true
process-exclude: bash
no-stdout: true
tcp-format: json
tcp-target: 127.0.0.1:1514
trace: true
udp-format: syslog
udp-target: 127.0.0.1:1515
ringbuf-size: 4096
correlation-cache: 8192
throttle-rate: 2.5
throttle-burst: 10
min-level: medium
verbose: true
stats-interval: 30
sigma-no-collapse-ws: true
pprof-listen: 127.0.0.1:6060
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	params := DefaultParameters()
	if err := ApplyConfigFile(cfgPath, &params); err != nil {
		t.Fatalf("ApplyConfigFile() error = %v", err)
	}

	if len(params.RuleDirs) != 1 || params.RuleDirs[0] != "/tmp/rules/linux" {
		t.Fatalf("RuleDirs = %#v, want [/tmp/rules/linux]", params.RuleDirs)
	}
	if len(params.AuditLogFiles) != 1 || params.AuditLogFiles[0] != "/var/log/audit/audit.log" {
		t.Fatalf("AuditLogFiles = %#v, want [/var/log/audit/audit.log]", params.AuditLogFiles)
	}
	if params.FilenameIOCPath != "/tmp/filename-iocs.txt" {
		t.Fatalf("FilenameIOCPath = %q, want /tmp/filename-iocs.txt", params.FilenameIOCPath)
	}
	if params.C2IOCPath != "/tmp/c2-iocs.txt" {
		t.Fatalf("C2IOCPath = %q, want /tmp/c2-iocs.txt", params.C2IOCPath)
	}
	if params.LogFile != "/tmp/aurora.log" || params.LogFileFormat != "syslog" {
		t.Fatalf("logfile settings not applied: %#v", params)
	}
	if !params.JSONOutput || !params.LowPrio || !params.NoStdout || !params.Trace || !params.Verbose {
		t.Fatalf("boolean settings not applied: %#v", params)
	}
	if params.ProcessExclude != "bash" {
		t.Fatalf("ProcessExclude = %q, want bash", params.ProcessExclude)
	}
	if params.TCPFormat != "json" || params.TCPTarget != "127.0.0.1:1514" {
		t.Fatalf("tcp settings not applied: format=%q target=%q", params.TCPFormat, params.TCPTarget)
	}
	if params.UDPFormat != "syslog" || params.UDPTarget != "127.0.0.1:1515" {
		t.Fatalf("udp settings not applied: format=%q target=%q", params.UDPFormat, params.UDPTarget)
	}
	if params.RingBufSizePages != 4096 || params.CorrelationCacheSize != 8192 {
		t.Fatalf("numeric settings not applied: ringbuf=%d cache=%d", params.RingBufSizePages, params.CorrelationCacheSize)
	}
	if params.ThrottleRate != 2.5 || params.ThrottleBurst != 10 {
		t.Fatalf("throttle settings not applied: rate=%v burst=%d", params.ThrottleRate, params.ThrottleBurst)
	}
	if params.MinLevel != "medium" || params.StatsInterval != 30 {
		t.Fatalf("min-level/stats settings not applied: min-level=%q stats=%d", params.MinLevel, params.StatsInterval)
	}
	if !params.SigmaNoCollapseWS {
		t.Fatalf("SigmaNoCollapseWS = %v, want true", params.SigmaNoCollapseWS)
	}
	if params.PprofListen != "127.0.0.1:6060" {
		t.Fatalf("PprofListen = %q, want 127.0.0.1:6060", params.PprofListen)
	}
}

func TestApplyConfigFileRejectsUnknownKey(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "aurora.yml")
	if err := os.WriteFile(cfgPath, []byte("unknown-key: 1\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	params := DefaultParameters()
	if err := ApplyConfigFile(cfgPath, &params); err == nil {
		t.Fatal("ApplyConfigFile() expected strict YAML parsing error")
	}
}
