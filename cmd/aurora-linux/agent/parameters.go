package agent

// Parameters holds all configuration options for the agent.
type Parameters struct {
	// Version is the Aurora Linux version displayed in startup output.
	Version string

	// RuleDirs contains directories with Sigma YAML rules.
	RuleDirs []string

	// LogFile is the path to the output log file. Empty means stdout only.
	LogFile string

	// JSONOutput enables JSON output format.
	JSONOutput bool

	// RingBufSizePages is the ring buffer size in pages (must be power of 2).
	RingBufSizePages int

	// CorrelationCacheSize is the LRU cache size for parent process correlation.
	CorrelationCacheSize int

	// ThrottleRate is the max Sigma matches per rule per second.
	ThrottleRate float64

	// ThrottleBurst is the burst size for the per-rule throttle.
	ThrottleBurst int

	// Verbose enables debug-level logging.
	Verbose bool

	// StatsInterval is how often to log processing stats (seconds). 0 = disabled.
	StatsInterval int
}

// DefaultParameters returns parameters with sensible defaults.
func DefaultParameters() Parameters {
	return Parameters{
		Version:              "dev",
		RingBufSizePages:     2048, // 8 MB
		CorrelationCacheSize: 16384,
		ThrottleRate:         1.0,
		ThrottleBurst:        5,
		StatsInterval:        60,
	}
}
