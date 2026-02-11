package main

import (
	"fmt"
	"os"

	"github.com/nicholasgasior/aurora-linux/cmd/aurora-linux/agent"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	params := agent.DefaultParameters()
	params.Version = version

	rootCmd := &cobra.Command{
		Use:   "aurora-linux",
		Short: "Aurora Linux EDR Agent",
		Long: `Aurora Linux is a standalone Linux EDR agent that collects system
telemetry via eBPF, normalizes events into a Sigma-compatible schema, and
matches them against Sigma rules in real time.`,
		Example: `  aurora-linux --rules /opt/sigma/rules/linux/process_creation --json
  aurora-linux --rules /opt/sigma/rules/linux/process_creation --rules /opt/sigma/rules/linux/network_connection --verbose`,
		Version:       version,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := agent.ValidateParameters(params); err != nil {
				return err
			}
			a := agent.New(params)
			return a.Run()
		},
	}

	flags := rootCmd.Flags()
	flags.StringSliceVar(&params.RuleDirs, "rules", nil, "Directories containing Sigma YAML rules (repeatable)")
	flags.StringVar(&params.LogFile, "logfile", "", "Output log file path (default: stdout)")
	flags.BoolVar(&params.JSONOutput, "json", false, "Enable JSON output format")
	flags.IntVar(&params.RingBufSizePages, "ringbuf-size", params.RingBufSizePages, "Ring buffer size in pages (must be power of 2; currently informational)")
	flags.IntVar(&params.CorrelationCacheSize, "correlation-cache", params.CorrelationCacheSize, "LRU cache size for parent process correlation")
	flags.Float64Var(&params.ThrottleRate, "throttle-rate", params.ThrottleRate, "Max Sigma matches per rule per second")
	flags.IntVar(&params.ThrottleBurst, "throttle-burst", params.ThrottleBurst, "Burst size for per-rule throttle")
	flags.BoolVarP(&params.Verbose, "verbose", "v", false, "Enable debug-level logging")
	flags.IntVar(&params.StatsInterval, "stats-interval", params.StatsInterval, "Stats logging interval in seconds (0=disabled)")
	_ = rootCmd.MarkFlagRequired("rules")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
