package agent

// Parameters holds all configuration options for the agent.
type Parameters struct {
	// Version is the Aurora Linux version displayed in startup output.
	Version string

	// RuleDirs contains directories with Sigma YAML rules.
	RuleDirs []string

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

	// NoStdout disables Sigma match logging to standard output.
	NoStdout bool

	// TCPFormat controls TCP output format (syslog or json).
	TCPFormat string

	// TCPTarget sends Sigma matches via TCP to host:port.
	TCPTarget string

	// Trace enables very-verbose event tracing logs.
	Trace bool

	// UDPFormat controls UDP output format (syslog or json).
	UDPFormat string

	// UDPTarget sends Sigma matches via UDP to host:port.
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
	// This can significantly reduce allocations at the cost of stricter whitespace matching.
	SigmaNoCollapseWS bool

	// PprofListen enables a local pprof HTTP endpoint on host:port.
	// Empty disables runtime profiling endpoints.
	PprofListen string
}

// DefaultParameters returns parameters with sensible defaults.
func DefaultParameters() Parameters {
	return Parameters{
		Version:              "0.1",
		RingBufSizePages:     2048, // 8 MB
		CorrelationCacheSize: 16384,
		ThrottleRate:         1.0,
		ThrottleBurst:        5,
		MinLevel:             "info",
		StatsInterval:        60,
	}
}
