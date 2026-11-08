package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sigmaconsumer "github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
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

	if strings.TrimSpace(params.FilenameIOCPath) != "" {
		if err := validateIOCFilePath("--filename-iocs", params.FilenameIOCPath); err != nil {
			return err
		}
	}
	if strings.TrimSpace(params.C2IOCPath) != "" {
		if err := validateIOCFilePath("--c2-iocs", params.C2IOCPath); err != nil {
			return err
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
	if !sigmaconsumer.IsValidMinLevel(params.MinLevel) {
		return fmt.Errorf("--min-level must be one of: info, low, medium, high, critical (got %q)", params.MinLevel)
	}
	if params.StatsInterval < 0 {
		return fmt.Errorf("--stats-interval must be >= 0, got %d", params.StatsInterval)
	}
	if strings.TrimSpace(params.PprofListen) != "" {
		if err := validateLoopbackHostPort("--pprof-listen", params.PprofListen); err != nil {
			return err
		}
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
	if err := validateConfiguredOutputFormat("--logfile-format", params.LogFileFormat); err != nil {
		return err
	}
	if err := validateConfiguredOutputFormat("--tcp-format", params.TCPFormat); err != nil {
		return err
	}
	if err := validateConfiguredOutputFormat("--udp-format", params.UDPFormat); err != nil {
		return err
	}
	if params.TCPTarget != "" {
		if err := validateHostPort("--tcp-target", params.TCPTarget); err != nil {
			return err
		}
	}
	if params.UDPTarget != "" {
		if err := validateHostPort("--udp-target", params.UDPTarget); err != nil {
			return err
		}
	}
	if params.NoStdout && params.LogFile == "" && params.TCPTarget == "" && params.UDPTarget == "" {
		return fmt.Errorf("--no-stdout requires at least one enabled sink: --logfile, --tcp-target, or --udp-target")
	}

	return nil
}

func isPowerOfTwo(v int) bool {
	return v > 0 && (v&(v-1)) == 0
}

func validateHostPort(flagName string, target string) error {
	target = strings.TrimSpace(target)
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("%s must be host:port (got %q): %w", flagName, target, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s must include a host (got %q)", flagName, target)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%s must include a numeric port (got %q)", flagName, target)
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("%s port must be in range 1-65535 (got %d)", flagName, portNum)
	}
	return nil
}

func validateLoopbackHostPort(flagName string, target string) error {
	target = strings.TrimSpace(target)
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("%s must be host:port (got %q): %w", flagName, target, err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("%s must include an explicit loopback host (got %q)", flagName, target)
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("%s host must be loopback (localhost, 127.0.0.1, or ::1), got %q", flagName, host)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%s must include a numeric port (got %q)", flagName, target)
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("%s port must be in range 1-65535 (got %d)", flagName, portNum)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateIOCFilePath(flagName, path string) error {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	st, err := os.Stat(cleanPath)
	if err != nil {
		return fmt.Errorf("%s file %q: %w", flagName, cleanPath, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s path %q must be a regular file", flagName, cleanPath)
	}
	return nil
}
