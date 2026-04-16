package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

type yamlConfig struct {
	Rules                []string `yaml:"rules"`
	FilenameIOCPath      *string  `yaml:"filename-iocs"`
	C2IOCPath            *string  `yaml:"c2-iocs"`
	LogFile              *string  `yaml:"logfile"`
	LogFileFormat        *string  `yaml:"logfile-format"`
	JSONOutput           *bool    `yaml:"json"`
	LowPrio              *bool    `yaml:"low-prio"`
	ProcessExclude       *string  `yaml:"process-exclude"`
	NoStdout             *bool    `yaml:"no-stdout"`
	TCPFormat            *string  `yaml:"tcp-format"`
	TCPTarget            *string  `yaml:"tcp-target"`
	Trace                *bool    `yaml:"trace"`
	UDPFormat            *string  `yaml:"udp-format"`
	UDPTarget            *string  `yaml:"udp-target"`
	RingBufSizePages     *int     `yaml:"ringbuf-size"`
	CorrelationCacheSize *int     `yaml:"correlation-cache"`
	ThrottleRate         *float64 `yaml:"throttle-rate"`
	ThrottleBurst        *int     `yaml:"throttle-burst"`
	MinLevel             *string  `yaml:"min-level"`
	Verbose              *bool    `yaml:"verbose"`
	StatsInterval        *int     `yaml:"stats-interval"`
	SigmaNoCollapseWS    *bool    `yaml:"sigma-no-collapse-ws"`
	PprofListen          *string  `yaml:"pprof-listen"`
	DryRun               *bool    `yaml:"dry-run"`
}

// ApplyConfigFile loads YAML configuration from path and applies only fields
// present in the YAML to the provided parameter struct.
func ApplyConfigFile(path string, params *Parameters) error {
	if params == nil {
		return fmt.Errorf("nil parameters")
	}

	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" {
		return fmt.Errorf("empty config path")
	}

	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return fmt.Errorf("reading config file %q: %w", cleanPath, err)
	}

	var cfg yamlConfig
	if err := yaml.UnmarshalStrict(raw, &cfg); err != nil {
		return fmt.Errorf("parsing config file %q: %w", cleanPath, err)
	}

	if cfg.Rules != nil {
		params.RuleDirs = append([]string(nil), cfg.Rules...)
	}
	if cfg.FilenameIOCPath != nil {
		params.FilenameIOCPath = strings.TrimSpace(*cfg.FilenameIOCPath)
	}
	if cfg.C2IOCPath != nil {
		params.C2IOCPath = strings.TrimSpace(*cfg.C2IOCPath)
	}
	if cfg.LogFile != nil {
		params.LogFile = strings.TrimSpace(*cfg.LogFile)
	}
	if cfg.LogFileFormat != nil {
		params.LogFileFormat = strings.TrimSpace(*cfg.LogFileFormat)
	}
	if cfg.JSONOutput != nil {
		params.JSONOutput = *cfg.JSONOutput
	}
	if cfg.LowPrio != nil {
		params.LowPrio = *cfg.LowPrio
	}
	if cfg.ProcessExclude != nil {
		params.ProcessExclude = strings.TrimSpace(*cfg.ProcessExclude)
	}
	if cfg.NoStdout != nil {
		params.NoStdout = *cfg.NoStdout
	}
	if cfg.TCPFormat != nil {
		params.TCPFormat = strings.TrimSpace(*cfg.TCPFormat)
	}
	if cfg.TCPTarget != nil {
		params.TCPTarget = strings.TrimSpace(*cfg.TCPTarget)
	}
	if cfg.Trace != nil {
		params.Trace = *cfg.Trace
	}
	if cfg.UDPFormat != nil {
		params.UDPFormat = strings.TrimSpace(*cfg.UDPFormat)
	}
	if cfg.UDPTarget != nil {
		params.UDPTarget = strings.TrimSpace(*cfg.UDPTarget)
	}
	if cfg.RingBufSizePages != nil {
		params.RingBufSizePages = *cfg.RingBufSizePages
	}
	if cfg.CorrelationCacheSize != nil {
		params.CorrelationCacheSize = *cfg.CorrelationCacheSize
	}
	if cfg.ThrottleRate != nil {
		params.ThrottleRate = *cfg.ThrottleRate
	}
	if cfg.ThrottleBurst != nil {
		params.ThrottleBurst = *cfg.ThrottleBurst
	}
	if cfg.MinLevel != nil {
		params.MinLevel = strings.TrimSpace(*cfg.MinLevel)
	}
	if cfg.Verbose != nil {
		params.Verbose = *cfg.Verbose
	}
	if cfg.StatsInterval != nil {
		params.StatsInterval = *cfg.StatsInterval
	}
	if cfg.SigmaNoCollapseWS != nil {
		params.SigmaNoCollapseWS = *cfg.SigmaNoCollapseWS
	}
	if cfg.PprofListen != nil {
		params.PprofListen = strings.TrimSpace(*cfg.PprofListen)
	}
	if cfg.DryRun != nil {
		params.DryRun = *cfg.DryRun
	}

	return nil
}
