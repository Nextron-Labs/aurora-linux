package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateParametersRejectsMissingRules(t *testing.T) {
	params := DefaultParameters()
	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for missing --rules")
	}
	if !strings.Contains(err.Error(), "--rules") {
		t.Fatalf("expected --rules hint, got %v", err)
	}
}

func TestValidateParametersRejectsInvalidRuleDirectory(t *testing.T) {
	params := DefaultParameters()
	params.RuleDirs = []string{"/definitely/does/not/exist"}

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for invalid rule directory")
	}
}

func TestValidateParametersRejectsRuleFilePath(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rule.yml")
	if err := os.WriteFile(ruleFile, []byte("title: test"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	params := DefaultParameters()
	params.RuleDirs = []string{ruleFile}
	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for non-directory rule path")
	}
}

func TestValidateParametersRejectsInvalidFilenameIOCPath(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.FilenameIOCPath = filepath.Join(tmpDir, "missing-filename-iocs.txt")

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for invalid --filename-iocs")
	}
	if !strings.Contains(err.Error(), "--filename-iocs") {
		t.Fatalf("expected --filename-iocs context, got %v", err)
	}
}

func TestValidateParametersRejectsInvalidC2IOCPath(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.C2IOCPath = filepath.Join(tmpDir, "missing-c2-iocs.txt")

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for invalid --c2-iocs")
	}
	if !strings.Contains(err.Error(), "--c2-iocs") {
		t.Fatalf("expected --c2-iocs context, got %v", err)
	}
}

func TestValidateParametersAcceptsValidIOCPaths(t *testing.T) {
	tmpDir := t.TempDir()
	filenameIOCPath := filepath.Join(tmpDir, "filename-iocs.txt")
	c2IOCPath := filepath.Join(tmpDir, "c2-iocs.txt")
	if err := os.WriteFile(filenameIOCPath, []byte("foo;80\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(c2IOCPath, []byte("example.com\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.FilenameIOCPath = filenameIOCPath
	params.C2IOCPath = c2IOCPath

	if err := ValidateParameters(params); err != nil {
		t.Fatalf("ValidateParameters() unexpected error: %v", err)
	}
}

func TestValidateParametersRejectsInvalidNumericValues(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.RingBufSizePages = 3

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for invalid ringbuf-size")
	}
	if !strings.Contains(err.Error(), "--ringbuf-size") {
		t.Fatalf("expected --ringbuf-size context, got %v", err)
	}
}

func TestValidateParametersRejectsInvalidMinLevel(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.MinLevel = "urgent"

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for invalid --min-level")
	}
	if !strings.Contains(err.Error(), "--min-level") {
		t.Fatalf("expected --min-level context, got %v", err)
	}
}

func TestValidateParametersRejectsMissingLogfileDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.LogFile = filepath.Join(tmpDir, "missing", "aurora.log")

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for missing logfile directory")
	}
	if !strings.Contains(err.Error(), "logfile directory") {
		t.Fatalf("expected logfile directory context, got %v", err)
	}
}

func TestValidateParametersAcceptsValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.LogFile = filepath.Join(tmpDir, "aurora.log")

	if err := ValidateParameters(params); err != nil {
		t.Fatalf("ValidateParameters() unexpected error: %v", err)
	}
}

func TestValidateParametersRejectsInvalidOutputFormat(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.LogFileFormat = "plain"

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for invalid --logfile-format")
	}
	if !strings.Contains(err.Error(), "--logfile-format") {
		t.Fatalf("expected --logfile-format context, got %v", err)
	}
}

func TestValidateParametersRejectsInvalidTCPTarget(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.TCPTarget = "bad-target"

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for invalid --tcp-target")
	}
	if !strings.Contains(err.Error(), "--tcp-target") {
		t.Fatalf("expected --tcp-target context, got %v", err)
	}
}

func TestValidateParametersRejectsNoStdoutWithoutOtherSinks(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.NoStdout = true

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for --no-stdout without alternate sinks")
	}
	if !strings.Contains(err.Error(), "--no-stdout") {
		t.Fatalf("expected --no-stdout context, got %v", err)
	}
}

func TestValidateParametersAcceptsNoStdoutWithUDPSink(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.NoStdout = true
	params.UDPTarget = "127.0.0.1:514"

	if err := ValidateParameters(params); err != nil {
		t.Fatalf("ValidateParameters() unexpected error: %v", err)
	}
}

func TestValidateParametersRejectsNonLoopbackPprofListen(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.PprofListen = "0.0.0.0:6060"

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for non-loopback --pprof-listen")
	}
	if !strings.Contains(err.Error(), "--pprof-listen") {
		t.Fatalf("expected --pprof-listen context, got %v", err)
	}
}

func TestValidateParametersAcceptsLoopbackPprofListen(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.PprofListen = "127.0.0.1:6060"

	if err := ValidateParameters(params); err != nil {
		t.Fatalf("ValidateParameters() unexpected error: %v", err)
	}
}

func TestValidateHostPortWithPort0(t *testing.T) {
	err := validateHostPort("--tcp-target", "127.0.0.1:0")
	if err == nil {
		t.Fatal("validateHostPort() expected error for port 0")
	}
	if !strings.Contains(err.Error(), "1-65535") {
		t.Fatalf("expected port range error, got %v", err)
	}
}

func TestValidateHostPortWithPort65536(t *testing.T) {
	err := validateHostPort("--tcp-target", "127.0.0.1:65536")
	if err == nil {
		t.Fatal("validateHostPort() expected error for port 65536")
	}
	if !strings.Contains(err.Error(), "1-65535") {
		t.Fatalf("expected port range error, got %v", err)
	}
}

func TestValidateHostPortWithEmptyHost(t *testing.T) {
	err := validateHostPort("--tcp-target", ":8080")
	if err == nil {
		t.Fatal("validateHostPort() expected error for empty host")
	}
	if !strings.Contains(err.Error(), "must include a host") {
		t.Fatalf("expected host error, got %v", err)
	}
}

func TestValidateHostPortWithNonNumericPort(t *testing.T) {
	err := validateHostPort("--tcp-target", "localhost:abc")
	if err == nil {
		t.Fatal("validateHostPort() expected error for non-numeric port")
	}
	if !strings.Contains(err.Error(), "numeric port") {
		t.Fatalf("expected numeric port error, got %v", err)
	}
}

func TestIsLoopbackHostWithBracketedIPv6(t *testing.T) {
	// Bracketed IPv6 notation like [::1] shouldn't parse as IP directly
	if isLoopbackHost("[::1]") {
		t.Fatal("isLoopbackHost([::1]) should return false (brackets not stripped)")
	}

	// Without brackets should work
	if !isLoopbackHost("::1") {
		t.Fatal("isLoopbackHost(::1) should return true")
	}
}

func TestIsLoopbackHostWithLocalhost(t *testing.T) {
	if !isLoopbackHost("localhost") {
		t.Fatal("isLoopbackHost(localhost) should return true")
	}
	if !isLoopbackHost("LOCALHOST") {
		t.Fatal("isLoopbackHost(LOCALHOST) should return true (case insensitive)")
	}
}

func TestIsLoopbackHostWithIPv4Loopback(t *testing.T) {
	if !isLoopbackHost("127.0.0.1") {
		t.Fatal("isLoopbackHost(127.0.0.1) should return true")
	}
	if !isLoopbackHost("127.0.0.255") {
		t.Fatal("isLoopbackHost(127.0.0.255) should return true")
	}
}

func TestIsLoopbackHostWithNonLoopback(t *testing.T) {
	if isLoopbackHost("192.168.1.1") {
		t.Fatal("isLoopbackHost(192.168.1.1) should return false")
	}
	if isLoopbackHost("example.com") {
		t.Fatal("isLoopbackHost(example.com) should return false")
	}
	if isLoopbackHost("0.0.0.0") {
		t.Fatal("isLoopbackHost(0.0.0.0) should return false")
	}
}

func TestValidateLoopbackHostPortWithBracketedIPv6(t *testing.T) {
	// [::1] is valid IPv6 notation for net.SplitHostPort
	// After splitting, host = "::1" which is loopback
	// However, isLoopbackHost receives "::1" (without brackets)
	err := validateLoopbackHostPort("--pprof-listen", "[::1]:6060")
	if err != nil {
		t.Fatalf("validateLoopbackHostPort([::1]:6060) unexpected error: %v", err)
	}
}

func TestValidateLoopbackHostPortWithUnbracketedIPv6(t *testing.T) {
	// Unbracketed IPv6 with port is ambiguous and should fail parsing
	err := validateLoopbackHostPort("--pprof-listen", "::1:6060")
	// This will fail because ::1:6060 is ambiguous (colons in IPv6)
	if err == nil {
		t.Fatal("validateLoopbackHostPort() expected error for ambiguous IPv6")
	}
}

func TestIsPowerOfTwo(t *testing.T) {
	tests := []struct {
		value int
		want  bool
	}{
		{0, false},
		{1, true},
		{2, true},
		{3, false},
		{4, true},
		{5, false},
		{1024, true},
		{2048, true},
		{3000, false},
		{-1, false},
		{-2, false},
	}

	for _, tc := range tests {
		if got := isPowerOfTwo(tc.value); got != tc.want {
			t.Errorf("isPowerOfTwo(%d) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestValidateParametersRejectsEmptyRulesPath(t *testing.T) {
	params := DefaultParameters()
	params.RuleDirs = []string{"   "}

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for empty rules path")
	}
}

func TestValidateParametersRejectsZeroCorrelationCache(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.CorrelationCacheSize = 0

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for zero correlation cache")
	}
	if !strings.Contains(err.Error(), "--correlation-cache") {
		t.Fatalf("expected --correlation-cache context, got %v", err)
	}
}

func TestValidateParametersRejectsNegativeThrottleRate(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.ThrottleRate = -1

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for negative throttle rate")
	}
	if !strings.Contains(err.Error(), "--throttle-rate") {
		t.Fatalf("expected --throttle-rate context, got %v", err)
	}
}

func TestValidateParametersRejectsThrottleRateWithoutBurst(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.ThrottleRate = 1.0
	params.ThrottleBurst = 0

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for throttle rate without burst")
	}
	if !strings.Contains(err.Error(), "--throttle-burst") {
		t.Fatalf("expected --throttle-burst context, got %v", err)
	}
}

func TestValidateParametersRejectsNegativeStatsInterval(t *testing.T) {
	tmpDir := t.TempDir()
	params := DefaultParameters()
	params.RuleDirs = []string{tmpDir}
	params.StatsInterval = -1

	err := ValidateParameters(params)
	if err == nil {
		t.Fatal("ValidateParameters() expected error for negative stats interval")
	}
	if !strings.Contains(err.Error(), "--stats-interval") {
		t.Fatalf("expected --stats-interval context, got %v", err)
	}
}
