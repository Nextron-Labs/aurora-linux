package syslog

import (
	"os"
	"os/exec"
)

// DefaultCandidatePaths lists the syslog file paths that are commonly
// populated on mainstream Linux distributions. The list is ordered so
// that distro-specific aggregate logs come first; auth-only logs come
// after to avoid duplicating events when both are populated.
//
//   - /var/log/syslog       Debian, Ubuntu, Mint, Pop!_OS, Kali, RaspiOS
//   - /var/log/messages     RHEL, CentOS, Rocky, AlmaLinux, Fedora,
//                           Amazon Linux, Oracle Linux, SUSE,
//                           openSUSE, Arch (rsyslog), Gentoo
//   - /var/log/auth.log     Debian/Ubuntu authentication
//   - /var/log/secure       RHEL-family authentication
//   - /var/log/kern.log     Debian/Ubuntu kernel-only
//   - /var/log/daemon.log   Debian/Ubuntu daemon-only
func DefaultCandidatePaths() []string {
	return []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/kern.log",
		"/var/log/daemon.log",
	}
}

// DetectSyslogFiles returns the subset of DefaultCandidatePaths that is
// present and openable on the current host. Empty slice means none of
// the candidates is currently available.
func DetectSyslogFiles() []string {
	return detectFromCandidates(DefaultCandidatePaths())
}

func detectFromCandidates(candidates []string) []string {
	var found []string
	for _, p := range candidates {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !st.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		_ = f.Close()
		found = append(found, p)
	}
	return found
}

// JournaldAvailable reports whether journalctl is on PATH (used as the
// fallback source on systemd-only distros that have no plain-text syslog).
func JournaldAvailable() bool {
	_, err := exec.LookPath(defaultJournalctlBinary)
	return err == nil
}

// AutoDetectConfig builds a Config by probing the default file paths and
// falling back to journald when no file source is available. ok is false
// when neither files nor journald are usable on this host (the caller
// should turn this into a startup error).
func AutoDetectConfig() (cfg Config, ok bool) {
	files := DetectSyslogFiles()
	if len(files) > 0 {
		return Config{Files: files}, true
	}
	if JournaldAvailable() {
		return Config{UseJournald: true}, true
	}
	return Config{}, false
}
