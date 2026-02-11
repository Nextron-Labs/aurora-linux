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
