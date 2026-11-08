package ebpf

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestReadExeLinkCurrentProcess(t *testing.T) {
	// Read our own process exe link
	pid := uint32(os.Getpid())
	got, err := readExeLink(pid)
	if err != nil {
		t.Fatalf("readExeLink(%d) error = %v", pid, err)
	}
	if got == "" {
		t.Fatal("readExeLink() returned empty string")
	}
	// Should be a go test binary
	if !filepath.IsAbs(got) {
		t.Fatalf("readExeLink() = %q, expected absolute path", got)
	}
}

func TestReadExeLinkInvalidPid(t *testing.T) {
	_, err := readExeLink(999999999) // unlikely to exist
	if err == nil {
		t.Fatal("readExeLink(invalid PID) expected error")
	}
}

func TestReadCmdlineCurrentProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	got, err := readCmdline(pid)
	if err != nil {
		t.Fatalf("readCmdline(%d) error = %v", pid, err)
	}
	// cmdline contains NUL-separated args, should at least have the test binary
	if len(got) == 0 {
		t.Fatal("readCmdline() returned empty bytes")
	}
}

func TestReadCmdlineInvalidPid(t *testing.T) {
	_, err := readCmdline(999999999)
	if err == nil {
		t.Fatal("readCmdline(invalid PID) expected error")
	}
}

func TestReadCwdCurrentProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	got, err := readCwd(pid)
	if err != nil {
		t.Fatalf("readCwd(%d) error = %v", pid, err)
	}
	if got == "" {
		t.Fatal("readCwd() returned empty string")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("readCwd() = %q, expected absolute path", got)
	}
}

func TestReadCwdInvalidPid(t *testing.T) {
	_, err := readCwd(999999999)
	if err == nil {
		t.Fatal("readCwd(invalid PID) expected error")
	}
}

func TestReadLoginUIDCurrentProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	got := readLoginUID(pid)
	// loginuid may be unset (returns "") or a numeric string
	// We just verify it doesn't panic and returns something sensible
	if got != "" {
		// If set, should be parseable as int
		_, err := strconv.Atoi(got)
		if err != nil {
			t.Fatalf("readLoginUID() = %q, not a valid UID", got)
		}
	}
}

func TestReadLoginUIDInvalidPid(t *testing.T) {
	got := readLoginUID(999999999)
	if got != "" {
		t.Fatalf("readLoginUID(invalid PID) = %q, want empty string", got)
	}
}

func TestReadLoginUIDUnsetValue(t *testing.T) {
	// Test that loginUIDUnset constant is handled correctly
	if loginUIDUnset != "4294967295" {
		t.Fatalf("loginUIDUnset = %q, want 4294967295", loginUIDUnset)
	}
}

func TestReadFdLinkCurrentProcessStdout(t *testing.T) {
	pid := uint32(os.Getpid())
	// fd 1 is stdout, usually valid
	got, err := readFdLink(pid, 1)
	if err != nil {
		t.Fatalf("readFdLink(%d, 1) error = %v", pid, err)
	}
	// Should be something like /dev/pts/N or pipe: or similar
	if got == "" {
		t.Fatal("readFdLink() returned empty string")
	}
}

func TestReadFdLinkInvalidFd(t *testing.T) {
	pid := uint32(os.Getpid())
	_, err := readFdLink(pid, 99999) // unlikely to exist
	if err == nil {
		t.Fatal("readFdLink(invalid fd) expected error")
	}
}

func TestResolveFilenameAbsolutePath(t *testing.T) {
	// Absolute path should be returned (possibly with symlinks resolved)
	got := resolveFilename(uint32(os.Getpid()), "/etc/passwd", -100)
	if got == "" {
		t.Fatal("resolveFilename() returned empty for absolute path")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("resolveFilename(/etc/passwd) = %q, expected absolute", got)
	}
}

func TestResolveFilenameRelativeWithATFDCWD(t *testing.T) {
	pid := uint32(os.Getpid())
	cwd, _ := os.Getwd()

	// AT_FDCWD = -100 means resolve relative to cwd
	got := resolveFilename(pid, "testfile.txt", -100)

	// Should be cwd + testfile.txt (even if file doesn't exist)
	expected := filepath.Join(cwd, "testfile.txt")
	if got != expected {
		t.Fatalf("resolveFilename(relative, AT_FDCWD) = %q, want %q", got, expected)
	}
}

func TestResolveFilenameInvalidPid(t *testing.T) {
	// Invalid PID for relative path resolution
	got := resolveFilename(999999999, "relative.txt", -100)
	// Should return the original filename when cwd can't be read
	if got != "relative.txt" {
		t.Fatalf("resolveFilename(invalid PID) = %q, want relative.txt", got)
	}
}

func TestResolveFilenameWithSymlinks(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file
	realFile := filepath.Join(tmpDir, "real.txt")
	if err := os.WriteFile(realFile, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	// Create a symlink to it
	symlink := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatalf("Symlink error: %v", err)
	}

	// resolveFilename should resolve the symlink
	got := resolveFilename(uint32(os.Getpid()), symlink, -100)
	if got != realFile {
		t.Fatalf("resolveFilename(symlink) = %q, want %q", got, realFile)
	}
}

func TestMaxCmdlineBytesConstant(t *testing.T) {
	if maxCmdlineBytes != 32768 {
		t.Fatalf("maxCmdlineBytes = %d, want 32768", maxCmdlineBytes)
	}
}
