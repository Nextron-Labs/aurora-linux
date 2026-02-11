package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
