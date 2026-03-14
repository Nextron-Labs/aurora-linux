package agent

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

func TestRunFailsWhenRuleDirectoriesYieldNoLoadableRules(t *testing.T) {
	params := DefaultParameters()
	params.RuleDirs = []string{t.TempDir()}
	params.StatsInterval = 0

	a := New(params)
	err := a.Run()
	if err == nil {
		t.Fatal("Run() expected error when no Sigma rules can be loaded")
	}
	if !strings.Contains(err.Error(), "loading Sigma rules") {
		t.Fatalf("Run() error = %q, want loading Sigma rules context", err.Error())
	}
}

func TestCloseLogFileIsIdempotent(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "aurora-log-*.log")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}

	a := &Agent{logFile: f}
	a.closeLogFile()
	if a.logFile != nil {
		t.Fatal("logFile should be nil after first close")
	}

	// Second call should be a no-op.
	a.closeLogFile()

	if _, err := f.WriteString("should fail"); err == nil {
		t.Fatal("expected writing to closed log file to fail")
	}
}

func TestConfigureLoggingJSONSplitsDiagnosticsAndNDJSON(t *testing.T) {
	standard := log.StandardLogger()
	origOut := standard.Out
	origFormatter := standard.Formatter
	origLevel := standard.GetLevel()
	t.Cleanup(func() {
		standard.SetOutput(origOut)
		standard.SetFormatter(origFormatter)
		standard.SetLevel(origLevel)
	})

	origStdout := os.Stdout
	origStderr := os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() for stdout failed: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		t.Fatalf("os.Pipe() for stderr failed: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	t.Cleanup(func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
	})

	params := DefaultParameters()
	params.JSONOutput = true

	a := New(params)
	matchLogger, err := a.configureLogging()
	if err != nil {
		t.Fatalf("configureLogging() error = %v", err)
	}
	if matchLogger == standard {
		t.Fatal("expected dedicated match logger in JSON mode")
	}

	log.WithField("phase", "startup").Info("diagnostic line")
	matchLogger.WithField("sigma_rule", "rule-1").Warn("Sigma match")

	if err := stdoutW.Close(); err != nil {
		t.Fatalf("closing stdout writer failed: %v", err)
	}
	if err := stderrW.Close(); err != nil {
		t.Fatalf("closing stderr writer failed: %v", err)
	}

	stdoutData, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("reading stdout failed: %v", err)
	}
	stderrData, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("reading stderr failed: %v", err)
	}

	stdoutText := string(stdoutData)
	stderrText := string(stderrData)

	if strings.Contains(stdoutText, "diagnostic line") {
		t.Fatalf("diagnostics leaked into stdout: %q", stdoutText)
	}
	if !strings.Contains(stderrText, "diagnostic line") {
		t.Fatalf("expected diagnostics in stderr, got %q", stderrText)
	}
	if strings.Contains(stderrText, `"sigma_rule"`) {
		t.Fatalf("NDJSON leaked into stderr: %q", stderrText)
	}
	if !strings.HasSuffix(stderrText, "\n") {
		t.Fatalf("stderr diagnostics must be newline-terminated, got %q", stderrText)
	}

	stderrLines := strings.Split(strings.TrimSpace(stderrText), "\n")
	if len(stderrLines) != 1 {
		t.Fatalf("expected one stderr line, got %d lines in %q", len(stderrLines), stderrText)
	}

	var diagPayload map[string]interface{}
	if err := json.Unmarshal([]byte(stderrLines[0]), &diagPayload); err != nil {
		t.Fatalf("stderr line is not valid JSON: %v (line=%q)", err, stderrLines[0])
	}
	if got, _ := diagPayload["message"].(string); got != "diagnostic line" {
		t.Fatalf("stderr JSON message = %q, want diagnostic line", got)
	}

	if !strings.HasSuffix(stdoutText, "\n") {
		t.Fatalf("stdout NDJSON must be newline-terminated, got %q", stdoutText)
	}

	lines := strings.Split(strings.TrimSpace(stdoutText), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one NDJSON line, got %d lines in %q", len(lines), stdoutText)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("stdout line is not valid JSON: %v (line=%q)", err, lines[0])
	}
	if got, _ := payload["sigma_rule"].(string); got != "rule-1" {
		t.Fatalf("stdout JSON sigma_rule = %q, want rule-1", got)
	}
	if got, _ := payload["message"].(string); got != "Sigma match" {
		t.Fatalf("stdout JSON message = %q, want Sigma match", got)
	}
}

func TestOpenSecureLogFileRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.log")
	if err := os.WriteFile(target, []byte(""), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	linkPath := filepath.Join(tmpDir, "link.log")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	f, err := openSecureLogFile(linkPath)
	if err == nil {
		_ = f.Close()
		t.Fatal("openSecureLogFile() expected symlink rejection")
	}
}

func TestOpenSecureLogFileCreatesPrivateRegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "aurora.log")

	f, err := openSecureLogFile(logPath)
	if err != nil {
		t.Fatalf("openSecureLogFile() error = %v", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !st.Mode().IsRegular() {
		t.Fatalf("expected regular file, got mode %v", st.Mode())
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("expected logfile permissions without group/other access, got %o", st.Mode().Perm())
	}
}

func TestOpenSecureLogFileRejectsDeviceNode(t *testing.T) {
	f, err := openSecureLogFile("/dev/null")
	if err == nil {
		_ = f.Close()
		t.Fatal("openSecureLogFile() expected non-regular file rejection")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("unexpected error for device node: %v", err)
	}
}

func TestOpenSecureLogFileNoFollowFlagSet(t *testing.T) {
	if syscall.O_NOFOLLOW == 0 {
		t.Fatal("expected O_NOFOLLOW to be non-zero on supported platforms")
	}
}

func TestShouldExcludeEventMatchesImageAndCommandLine(t *testing.T) {
	a := New(Parameters{ProcessExclude: "bash"})

	evt := &stubEvent{
		id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 1},
		source: "LinuxEBPF:ProcessExec",
		fields: enrichment.DataFieldsMap{
			"Image":       enrichment.NewStringValue("/usr/bin/bash"),
			"CommandLine": enrichment.NewStringValue("bash -c whoami"),
		},
	}
	if !a.shouldExcludeEvent(evt) {
		t.Fatal("shouldExcludeEvent() expected true for matching process fields")
	}

	a.params.ProcessExclude = "python"
	if a.shouldExcludeEvent(evt) {
		t.Fatal("shouldExcludeEvent() expected false for non-matching filter")
	}
}

type stubEvent struct {
	id     provider.EventIdentifier
	source string
	fields enrichment.DataFieldsMap
}

func (s *stubEvent) ID() provider.EventIdentifier { return s.id }
func (s *stubEvent) Process() uint32              { return 0 }
func (s *stubEvent) Source() string               { return s.source }
func (s *stubEvent) Time() time.Time              { return time.Unix(0, 0) }
func (s *stubEvent) Value(fieldname string) enrichment.DataValue {
	return s.fields.Value(fieldname)
}
func (s *stubEvent) ForEach(fn func(key string, value string)) { s.fields.ForEach(fn) }
