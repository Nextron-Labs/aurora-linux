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
