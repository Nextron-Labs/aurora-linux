package agent

import (
	"fmt"
	"strings"
)

// Parameters holds all configuration options for the agent.
type Parameters struct {
	// Version is the Aurora Linux version displayed in startup output.
	Version string

	// RuleDirs contains directories with Sigma YAML rules.
	RuleDirs []string

	// FilenameIOCPath points to the filename IOC definitions file.
	// Empty uses the default path near the aurora binary.
	FilenameIOCPath string

	// C2IOCPath points to the C2 IOC definitions file.
	// Empty uses the default path near the aurora binary.
	C2IOCPath string

	// LogFile is the path to the output log file. Empty means stdout only.
	LogFile string

	// LogFileFormat controls log file output format (syslog or json).
	LogFileFormat string

	// JSONOutput enables JSON output format.
	JSONOutput bool

	// LowPrio lowers process scheduling priority for reduced host impact.
	LowPrio bool

	// ProcessExclude excludes events whose process fields match this substring.
	ProcessExclude string

	// NoStdout disables match logging to standard output.
	NoStdout bool

	// TCPFormat controls TCP output format (syslog or json).
	TCPFormat string

	// TCPTarget sends match alerts via TCP to host:port.
	TCPTarget string

	// Trace enables very-verbose event tracing logs.
	Trace bool

	// UDPFormat controls UDP output format (syslog or json).
	UDPFormat string

	// UDPTarget sends match alerts via UDP to host:port.
	UDPTarget string

	// RingBufSizePages is the ring buffer size in pages (must be power of 2).
	RingBufSizePages int

	// CorrelationCacheSize is the LRU cache size for parent process correlation.
	CorrelationCacheSize int

	// ThrottleRate is the max Sigma matches per rule per second.
	ThrottleRate float64

	// ThrottleBurst is the burst size for the per-rule throttle.
	ThrottleBurst int

	// MinLevel is the minimum Sigma rule level loaded at initialization.
	MinLevel string

	// Verbose enables debug-level logging.
	Verbose bool

	// StatsInterval is how often to log processing stats (seconds). 0 = disabled.
	StatsInterval int

	// SigmaNoCollapseWS disables sigma whitespace collapsing during pattern matching.
	// Enabled by default to avoid high regex allocation churn in long-running agents.
	// Set to false to preserve sigma whitespace normalization behavior.
	SigmaNoCollapseWS bool

	// PprofListen enables a local pprof HTTP endpoint on host:port.
	// Empty disables runtime profiling endpoints.
	PprofListen string

	// SyslogFiles lists syslog-style log files to tail (optional input for the
	// Sigma linux syslog/auth/sshd/cron/... rules). Empty = disabled.
	SyslogFiles []string

	// SyslogJournal also follows the systemd journal (needs journalctl).
	SyslogJournal bool

	// TamperProtection selects the anti-tamper mode: "detect" (default; alerts
	// on attempts to kill/debug Aurora or interfere with its eBPF programs,
	// hardens the process, verifies sensors with a canary), "enforce" (adds
	// BPF-LSM deny hooks; blocks other tracing eBPF tools) or "off".
	TamperProtection string

	// StrictRules makes startup fail if any Sigma rule cannot be loaded or can
	// never match on this host (unsupported logsource or fields).
	StrictRules bool

	// AuditMode selects where auditd-compatible records (the input of the
	// SigmaHQ linux/auditd rules) come from:
	//   "ebpf"   (default) synthesised natively from eBPF; no auditd needed
	//   "auditd" tail auditd log files instead (optional, needs auditd)
	//   "both"   eBPF records plus auditd log files
	//   "off"    do not produce auditd-compatible records
	// When empty the mode is "ebpf".
	AuditMode string

	// AuditLogFiles contains paths to auditd log files for the audit provider
	// (only used in auditd mode).
	AuditLogFiles []string
}

// Audit modes accepted by Parameters.AuditMode.
const (
	AuditModeEBPF   = "ebpf"
	AuditModeAuditd = "auditd"
	AuditModeBoth   = "both"
	AuditModeOff    = "off"

	// DefaultAuditLogPath is used in auditd mode when no --audit-log is given.
	DefaultAuditLogPath = "/var/log/audit/audit.log"
)

// ResolveAuditMode returns the effective, validated audit mode.
func (p Parameters) ResolveAuditMode() (string, error) {
	mode := strings.ToLower(strings.TrimSpace(p.AuditMode))
	switch mode {
	case "":
		if len(p.AuditLogFiles) > 0 {
			// Before --audit-mode existed, --audit-log alone meant "tail
			// these auditd logs": keep existing deployments working.
			return AuditModeAuditd, nil
		}
		return AuditModeEBPF, nil
	case AuditModeEBPF, AuditModeAuditd, AuditModeBoth, AuditModeOff:
		return mode, nil
	}
	return "", fmt.Errorf("--audit-mode must be one of: ebpf, auditd, both, off (got %q)", p.AuditMode)
}

// DefaultParameters returns parameters with sensible defaults.
func DefaultParameters() Parameters {
	return Parameters{
		Version:              "0.1.4",
		RingBufSizePages:     2048, // 8 MB
		CorrelationCacheSize: 16384,
		ThrottleRate:         1.0,
		ThrottleBurst:        5,
		MinLevel:             "info",
		StatsInterval:        60,
		SigmaNoCollapseWS:    true,
	}
}
