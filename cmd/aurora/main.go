package main

import (
	"encoding/json"
	"fmt"
	ebpfprovider "github.com/Nextron-Labs/aurora-linux/lib/provider/ebpf"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Nextron-Labs/aurora-linux/cmd/aurora/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var version = "0.2.0"

func main() {
	// Anti-tamper canary helper: spawned by Aurora itself, never by users.
	if len(os.Args) == 2 && (os.Args[1] == ebpfprovider.CanaryArg || os.Args[1] == ebpfprovider.CanaryStage2Arg) {
		if err := ebpfprovider.RunCanaryChild(os.Args[1]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	params := agent.DefaultParameters()
	params.Version = version
	var configPath string

	rootCmd := &cobra.Command{
		Use:   "aurora",
		Short: "Aurora Linux detection agent",
		Long:  helpLong(version),
		Example: `  aurora --rules /opt/sigma/rules/linux --json
  aurora --rules /opt/sigma/rules/linux --rules /opt/custom/sigma --verbose`,
		Version:       version,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams := params
			effective := cliParams

			if strings.TrimSpace(configPath) != "" {
				effective = agent.DefaultParameters()
				effective.Version = version

				if err := agent.ApplyConfigFile(configPath, &effective); err != nil {
					return err
				}
				applyCLIOverrides(cmd.Flags(), &effective, cliParams)
			}
			params = effective

			if err := agent.ValidateParameters(effective); err != nil {
				return err
			}
			a := agent.New(effective)
			return a.Run()
		},
	}

	flags := rootCmd.Flags()
	flags.StringVarP(&configPath, "config", "c", "", "Use parameters from this YAML file")
	flags.StringSliceVar(&params.RuleDirs, "rules", nil, "Directories containing Sigma YAML rules (repeatable)")
	flags.StringVar(&params.FilenameIOCPath, "filename-iocs", "", "Path to filename IOC definitions (default: resources/iocs/filename-iocs.txt near the binary)")
	flags.StringVar(&params.C2IOCPath, "c2-iocs", "", "Path to C2 IOC definitions (default: resources/iocs/c2-iocs.txt near the binary)")
	flags.StringVarP(&params.LogFile, "logfile", "l", "", "Path to log file (default: no log file)")
	flags.StringVar(&params.LogFileFormat, "logfile-format", "", "Format for log file output (syslog or json)")
	flags.BoolVar(&params.LowPrio, "low-prio", false, "Run Aurora Agent with low process priority")
	flags.StringVar(&params.ProcessExclude, "process-exclude", "", "Exclude processes that match this string")
	flags.BoolVar(&params.NoStdout, "no-stdout", false, "Disable logging to standard output")
	flags.StringVar(&params.TCPFormat, "tcp-format", "", "Format for logs sent via TCP (syslog or json)")
	flags.StringVar(&params.TCPTarget, "tcp-target", "", "Send logs to this TCP address (host:port)")
	flags.BoolVar(&params.Trace, "trace", false, "Print tracing information, including observed eBPF events (very verbose)")
	flags.StringVar(&params.UDPFormat, "udp-format", "", "Format for logs sent via UDP (syslog or json)")
	flags.StringVar(&params.UDPTarget, "udp-target", "", "Send logs to this UDP address (host:port)")
	flags.BoolVar(&params.JSONOutput, "json", false, "Enable JSON output format")
	flags.IntVar(&params.RingBufSizePages, "ringbuf-size", params.RingBufSizePages, "Ring buffer size in pages (must be power of 2; currently informational)")
	flags.IntVar(&params.CorrelationCacheSize, "correlation-cache", params.CorrelationCacheSize, "LRU cache size for parent process correlation")
	flags.Float64Var(&params.ThrottleRate, "throttle-rate", params.ThrottleRate, "Max Sigma matches per rule per second")
	flags.IntVar(&params.ThrottleBurst, "throttle-burst", params.ThrottleBurst, "Burst size for per-rule throttle")
	flags.StringVar(&params.MinLevel, "min-level", params.MinLevel, "Minimum Sigma rule level to load (info, low, medium, high, critical)")
	flags.BoolVarP(&params.Verbose, "verbose", "v", false, "Enable debug-level logging")
	flags.IntVar(&params.StatsInterval, "stats-interval", params.StatsInterval, "Stats logging interval in seconds (0=disabled)")
	flags.BoolVar(&params.SigmaNoCollapseWS, "sigma-no-collapse-ws", params.SigmaNoCollapseWS, "Disable sigma whitespace collapsing during pattern matching (default: true)")
	flags.StringVar(&params.PprofListen, "pprof-listen", "", "Enable pprof HTTP endpoint on loopback host:port (example: 127.0.0.1:6060)")
	flags.StringSliceVar(&params.SyslogFiles, "syslog-log", nil, "Optional: syslog-style log file to tail for the Sigma syslog/auth/sshd/cron rules (repeatable, e.g. /var/log/syslog, /var/log/auth.log, /var/log/messages)")
	flags.BoolVar(&params.SyslogJournal, "syslog-journal", false, "Optional: also follow the systemd journal as syslog input (needs journalctl)")
	flags.StringVar(&params.TamperProtection, "tamper-protection", "", "Anti-tamper mode: detect (default: alert on kill/ptrace/eBPF interference, canary self-test), enforce (also deny via BPF-LSM; blocks other tracing eBPF tools) or off")
	flags.BoolVar(&params.StrictRules, "strict-rules", false, "Fail at startup if any Sigma rule cannot be loaded or can never match on this host (unsupported logsource/fields)")
	flags.StringVar(&params.AuditMode, "audit-mode", "", "Source of auditd-compatible records for the Sigma linux/auditd rules: ebpf (default, no auditd needed), auditd (tail audit log instead), both, or off")
	flags.StringSliceVar(&params.AuditLogFiles, "audit-log", nil, "Paths to auditd log files to process (repeatable; default /var/log/audit/audit.log in --audit-mode auditd or both; without --audit-mode, implies --audit-mode auditd)")

	if err := rootCmd.Execute(); err != nil {
		writeCLIError(err, params.JSONOutput, os.Stderr)
		os.Exit(1)
	}
}

func helpLong(version string) string {
	prettyVersion := strings.TrimSpace(version)
	if prettyVersion == "" {
		prettyVersion = "0.1.4"
	}
	if !strings.HasPrefix(strings.ToLower(prettyVersion), "v") {
		prettyVersion = "v" + prettyVersion
	}

	lines := []string{
		"  __    _     ___   ___   ___    __",
		" / /\\  | | | | |_) / / \\ | |_)  / /\\",
		"/_/--\\ \\_\\_/ |_| \\ \\_\\_/ |_| \\ /_/--\\",
		"",
		"Real-Time Sigma Matching on Linux via eBPF",
		"",
		fmt.Sprintf("(c) Florian Roth, 2026, %s", prettyVersion),
		"",
		"Aurora Linux is a standalone Linux telemetry and detection agent that collects system",
		"telemetry via eBPF, normalizes events into a Sigma-compatible schema, and",
		"matches them against Sigma rules in real time.",
	}
	return strings.Join(lines, "\n")
}

func applyCLIOverrides(set *pflag.FlagSet, dst *agent.Parameters, cli agent.Parameters) {
	set.Visit(func(f *pflag.Flag) {
		switch f.Name {
		case "rules":
			dst.RuleDirs = append([]string(nil), cli.RuleDirs...)
		case "filename-iocs":
			dst.FilenameIOCPath = cli.FilenameIOCPath
		case "c2-iocs":
			dst.C2IOCPath = cli.C2IOCPath
		case "logfile":
			dst.LogFile = cli.LogFile
		case "logfile-format":
			dst.LogFileFormat = cli.LogFileFormat
		case "low-prio":
			dst.LowPrio = cli.LowPrio
		case "process-exclude":
			dst.ProcessExclude = cli.ProcessExclude
		case "no-stdout":
			dst.NoStdout = cli.NoStdout
		case "tcp-format":
			dst.TCPFormat = cli.TCPFormat
		case "tcp-target":
			dst.TCPTarget = cli.TCPTarget
		case "trace":
			dst.Trace = cli.Trace
		case "udp-format":
			dst.UDPFormat = cli.UDPFormat
		case "udp-target":
			dst.UDPTarget = cli.UDPTarget
		case "json":
			dst.JSONOutput = cli.JSONOutput
		case "ringbuf-size":
			dst.RingBufSizePages = cli.RingBufSizePages
		case "correlation-cache":
			dst.CorrelationCacheSize = cli.CorrelationCacheSize
		case "throttle-rate":
			dst.ThrottleRate = cli.ThrottleRate
		case "throttle-burst":
			dst.ThrottleBurst = cli.ThrottleBurst
		case "min-level":
			dst.MinLevel = cli.MinLevel
		case "verbose":
			dst.Verbose = cli.Verbose
		case "stats-interval":
			dst.StatsInterval = cli.StatsInterval
		case "sigma-no-collapse-ws":
			dst.SigmaNoCollapseWS = cli.SigmaNoCollapseWS
		case "pprof-listen":
			dst.PprofListen = cli.PprofListen
		case "syslog-log":
			dst.SyslogFiles = append([]string(nil), cli.SyslogFiles...)
		case "syslog-journal":
			dst.SyslogJournal = cli.SyslogJournal
		case "tamper-protection":
			dst.TamperProtection = cli.TamperProtection
		case "strict-rules":
			dst.StrictRules = cli.StrictRules
		case "audit-mode":
			dst.AuditMode = cli.AuditMode
		case "audit-log":
			dst.AuditLogFiles = append([]string(nil), cli.AuditLogFiles...)
		}
	})
}

func writeCLIError(err error, jsonOutput bool, out io.Writer) {
	if err == nil {
		return
	}

	if jsonOutput {
		entry := map[string]string{
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"level":     "error",
			"message":   err.Error(),
		}
		if encoded, marshalErr := json.Marshal(entry); marshalErr == nil {
			_, _ = out.Write(append(encoded, '\n'))
			return
		}
	}

	fmt.Fprintln(out, err)
}
