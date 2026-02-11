package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateParameters performs user-facing configuration validation before
// runtime initialization starts.
func ValidateParameters(params Parameters) error {
	if len(params.RuleDirs) == 0 {
		return fmt.Errorf(
			"at least one --rules directory is required (example: --rules /path/to/sigma/rules/linux/process_creation)",
		)
	}

	for _, dir := range params.RuleDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return fmt.Errorf("--rules cannot contain empty paths")
		}

		cleanDir := filepath.Clean(dir)
		st, err := os.Stat(cleanDir)
		if err != nil {
			return fmt.Errorf("rules directory %q: %w", cleanDir, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("rules path %q must be a directory", cleanDir)
		}
	}

	if params.RingBufSizePages <= 0 || !isPowerOfTwo(params.RingBufSizePages) {
		return fmt.Errorf("--ringbuf-size must be a positive power of 2, got %d", params.RingBufSizePages)
	}
	if params.CorrelationCacheSize <= 0 {
		return fmt.Errorf("--correlation-cache must be > 0, got %d", params.CorrelationCacheSize)
	}
	if params.ThrottleRate < 0 {
		return fmt.Errorf("--throttle-rate must be >= 0, got %v", params.ThrottleRate)
	}
	if params.ThrottleRate > 0 && params.ThrottleBurst <= 0 {
		return fmt.Errorf("--throttle-burst must be > 0 when throttling is enabled, got %d", params.ThrottleBurst)
	}
	if params.StatsInterval < 0 {
		return fmt.Errorf("--stats-interval must be >= 0, got %d", params.StatsInterval)
	}

	if params.LogFile != "" {
		logDir := filepath.Dir(filepath.Clean(params.LogFile))
		st, err := os.Stat(logDir)
		if err != nil {
			return fmt.Errorf("logfile directory %q: %w", logDir, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("logfile directory %q must be a directory", logDir)
		}
	}

	return nil
}

func isPowerOfTwo(v int) bool {
	return v > 0 && (v&(v-1)) == 0
}
