package ebpf

import (
	"path"
	"strings"
)

// This file is the eBPF replacement for the auditd rules (-w / -a ... -k) that
// the SigmaHQ linux/auditd rule set documents as prerequisites. Instead of
// configuring auditd, Aurora embeds the equivalent watches here.

// accessPerm mirrors the auditd "-p" permission letters.
type accessPerm uint8

const (
	permRead accessPerm = 1 << iota
	permWrite
	permAttr
	permAll = permRead | permWrite | permAttr
)

// watchRule is the equivalent of "auditctl -w <pattern> -p <perms> -k <key>".
type watchRule struct {
	// pattern is a glob; '*' matches any run of characters (including '/'),
	// which is the same semantics Sigma uses for wildcards.
	pattern string
	perms   accessPerm
	key     string
	// kernelPrefixes feed the in-kernel pre-filter. When empty the literal
	// part of pattern (up to the first '*') is used.
	kernelPrefixes []string
}

// hiddenHomePrefix is registered in the kernel filter with the "requires a
// hidden path component" flag so that /home/*/.bashrc style watches stay cheap.
const hiddenHomePrefix = "/home/"

// releaseFilePrefixes pre-filters "/etc/*release" and "/etc/*version".
var releaseFilePrefixes = []string{
	"/etc/os-", "/etc/lsb-", "/etc/redhat-", "/etc/centos-", "/etc/fedora-",
	"/etc/system-", "/etc/SuSE-", "/etc/alpine-", "/etc/arch-", "/etc/gentoo-",
	"/etc/rocky-", "/etc/almalinux-", "/etc/oracle-", "/etc/mandriva-",
	"/etc/debian_", "/etc/devuan_", "/etc/slackware-", "/etc/openwrt_",
	"/etc/issue",
}

const (
	permWA = permWrite | permAttr
)

// defaultAuditWatches lists every path that one of the SigmaHQ linux/auditd
// rules inspects through a PATH record.
//
// Permissions follow the intent of the corresponding auditd rules: tamper
// detections only care about modifications (wa) because the files are read
// constantly by legitimate software (e.g. /etc/ld.so.preload on every exec,
// /etc/pam.d/system-auth on every login); discovery detections watch reads.
var defaultAuditWatches = []watchRule{
	// lnx_auditd_auditing_config_change
	{pattern: "/etc/audit/*", perms: permWA, key: "auditconfig"},
	{pattern: "/etc/libaudit.conf", perms: permWA, key: "auditconfig"},
	{pattern: "/etc/audisp/*", perms: permWA, key: "audispconfig"},

	// lnx_auditd_bpfdoor_file_accessed
	{pattern: "/var/run/aepmonend.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/auditd.lock", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/cma.lock", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/console-kit.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/consolekit.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/daemon.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/hald-addon.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/hald-smartd.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/haldrund.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/hp-health.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/hpasmlit.lock", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/hpasmlited.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/kdevrund.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/lldpad.lock", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/mcelog.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/system.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/uvp-srv.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/vmtoolagt.pid", perms: permAll, key: "bpfdoor"},
	{pattern: "/var/run/xinetd.lock", perms: permAll, key: "bpfdoor"},

	// lnx_auditd_ld_so_preload_mod
	{pattern: "/etc/ld.so.preload", perms: permWA, key: "systemwide_preloads"},

	// lnx_auditd_logging_config_change
	{pattern: "/etc/syslog.conf", perms: permWA, key: "logging_config"},
	{pattern: "/etc/rsyslog.conf", perms: permWA, key: "logging_config"},
	{pattern: "/etc/syslog-ng/syslog-ng.conf", perms: permWA, key: "logging_config"},

	// lnx_auditd_magic_system_request_key
	{pattern: "/proc/sys/kernel/sysrq", perms: permWA, key: "sysrq"},
	{pattern: "/proc/sysrq-trigger", perms: permWA, key: "sysrq"},
	{pattern: "/etc/sysctl.conf", perms: permWA, key: "sysrq"},

	// lnx_auditd_systemd_service_creation (creation events only matter, the
	// nametype=CREATE decision is made per operation)
	{pattern: "/usr/lib/systemd/system/*", perms: permWrite, key: "systemd"},
	{pattern: "/etc/systemd/system/*", perms: permWrite, key: "systemd"},
	{pattern: "*/.config/systemd/user/*", perms: permWrite, key: "systemd",
		kernelPrefixes: []string{"/root/."}},

	// lnx_auditd_keylogging_with_pam_d
	{pattern: "/etc/pam.d/system-auth", perms: permWA, key: "pam"},
	{pattern: "/etc/pam.d/password-auth", perms: permWA, key: "pam"},

	// lnx_auditd_password_policy_discovery
	{pattern: "/etc/login.defs", perms: permRead, key: "password_policy"},
	{pattern: "/etc/pam.d/auth", perms: permRead, key: "password_policy"},
	{pattern: "/etc/pam.d/common-account", perms: permRead, key: "password_policy"},
	{pattern: "/etc/pam.d/common-auth", perms: permRead, key: "password_policy"},
	{pattern: "/etc/pam.d/common-password", perms: permRead, key: "password_policy"},
	{pattern: "/etc/security/pwquality.conf", perms: permRead, key: "password_policy"},

	// lnx_auditd_system_info_discovery / _discovery2
	{pattern: "/etc/lsb-release", perms: permRead, key: "system_info"},
	{pattern: "/etc/redhat-release", perms: permRead, key: "system_info"},
	{pattern: "/etc/issue", perms: permRead, key: "system_info"},
	{pattern: "/etc/*release", perms: permRead, key: "system_info", kernelPrefixes: releaseFilePrefixes},
	{pattern: "/etc/*version", perms: permRead, key: "system_info", kernelPrefixes: releaseFilePrefixes},
	{pattern: "/sys/class/dmi/id/bios_version", perms: permRead, key: "system_info"},
	{pattern: "/sys/class/dmi/id/product_name", perms: permRead, key: "system_info"},
	{pattern: "/sys/class/dmi/id/chassis_vendor", perms: permRead, key: "system_info"},
	{pattern: "/proc/scsi/scsi", perms: permRead, key: "system_info"},
	{pattern: "/proc/ide/hd0/model", perms: permRead, key: "system_info"},
	{pattern: "/proc/version", perms: permRead, key: "system_info"},

	// lnx_auditd_unix_shell_configuration_modification
	{pattern: "/etc/shells", perms: permWA, key: "shell_config"},
	{pattern: "/etc/profile", perms: permWA, key: "shell_config"},
	{pattern: "/etc/profile.d/*", perms: permWA, key: "shell_config"},
	{pattern: "/etc/bash.bashrc", perms: permWA, key: "shell_config"},
	{pattern: "/etc/bashrc", perms: permWA, key: "shell_config"},
	{pattern: "/etc/zsh/zprofile", perms: permWA, key: "shell_config"},
	{pattern: "/etc/zsh/zshrc", perms: permWA, key: "shell_config"},
	{pattern: "/etc/zsh/zlogin", perms: permWA, key: "shell_config"},
	{pattern: "/etc/zsh/zlogout", perms: permWA, key: "shell_config"},
	{pattern: "/etc/csh.cshrc", perms: permWA, key: "shell_config"},
	{pattern: "/etc/csh.login", perms: permWA, key: "shell_config"},
	{pattern: "/root/.bashrc", perms: permWA, key: "shell_config"},
	{pattern: "/root/.bash_profile", perms: permWA, key: "shell_config"},
	{pattern: "/root/.profile", perms: permWA, key: "shell_config"},
	{pattern: "/root/.zshrc", perms: permWA, key: "shell_config"},
	{pattern: "/root/.zprofile", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.bashrc", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.zshrc", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.bash_profile", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.zprofile", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.profile", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.bash_login", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.bash_logout", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.zlogin", perms: permWA, key: "shell_config"},
	{pattern: "/home/*/.zlogout", perms: permWA, key: "shell_config"},
}

// execWatchKeys reproduces "-w <binary> -p x -k susp_activity" from
// lnx_auditd_susp_c2_commands. Binaries in the standard bin directories match
// regardless of which of them (/bin, /usr/bin, /sbin, /usr/sbin) holds them.
var (
	execWatchNames = map[string]string{
		"nc": "susp_activity", "netcat": "susp_activity", "base64": "susp_activity",
		"curl": "susp_activity", "ftp": "susp_activity", "ncat": "susp_activity",
		"netstat": "susp_activity", "nmap": "susp_activity", "rawshark": "susp_activity",
		"rdesktop": "susp_activity", "scp": "susp_activity", "sftp": "susp_activity",
		"socat": "susp_activity", "ssh": "susp_activity", "ss": "susp_activity",
		"tshark": "susp_activity", "wget": "susp_activity", "wireshark": "susp_activity",
		"wlfreerdp": "susp_activity", "xfreerdp": "susp_activity",
	}
	execWatchLocalBin = map[string]string{
		"/usr/local/bin/rdesktop": "susp_activity",
		"/usr/local/bin/xfreerdp": "susp_activity",
	}
	standardBinDirs = map[string]struct{}{
		"/bin": {}, "/usr/bin": {}, "/sbin": {}, "/usr/sbin": {},
	}
)

// execKey returns the audit key for executing the binary at binPath.
func execKey(binPath string) string {
	if k, ok := execWatchLocalBin[binPath]; ok {
		return k
	}
	if _, ok := standardBinDirs[path.Dir(binPath)]; ok {
		return execWatchNames[path.Base(binPath)]
	}
	return ""
}

// connectKey is the key used by the upstream audit.rules for connect(2).
func connectKey(isIPv6 bool) string {
	if isIPv6 {
		return "network_connect_6"
	}
	return "network_connect_4"
}

// watchSet is a compiled collection of watchRules.
type watchSet struct {
	rules []watchRule
}

func newWatchSet(rules []watchRule) *watchSet {
	return &watchSet{rules: rules}
}

// match returns the key of the first rule that covers name for the given
// access intent.
func (w *watchSet) match(name string, intent accessPerm) (string, bool) {
	for i := range w.rules {
		r := &w.rules[i]
		if r.perms&intent == 0 {
			continue
		}
		if globMatch(r.pattern, name) {
			return r.key, true
		}
	}
	return "", false
}

// kernelPrefixes returns the deduplicated prefixes for the in-kernel filter
// along with the flag telling whether a hidden path component is required.
func (w *watchSet) kernelPrefixes() map[string]bool {
	out := make(map[string]bool)
	add := func(p string, needsHidden bool) {
		if p == "" {
			return
		}
		// The kernel reads the path head as a NUL-terminated string in
		// watchKeyBytes bytes, so at most watchKeyBytes-1 bytes can match.
		if len(p) > watchKeyBytes-1 {
			p = p[:watchKeyBytes-1]
		}
		// A plain entry always wins over a "needs hidden" one.
		if prev, ok := out[p]; ok && !prev {
			return
		}
		out[p] = needsHidden
	}
	for _, r := range w.rules {
		if len(r.kernelPrefixes) > 0 {
			for _, p := range r.kernelPrefixes {
				add(p, false)
			}
			continue
		}
		lit := r.pattern
		if i := strings.IndexByte(lit, '*'); i >= 0 {
			lit = lit[:i]
		}
		if strings.HasPrefix(lit, hiddenHomePrefix) {
			continue // covered by the hidden-component entry below
		}
		add(lit, false)
	}
	// /home/<user>/.dotfile and ~/.config/...: any hidden component under /home/
	add(hiddenHomePrefix, true)
	return out
}

// globMatch matches s against pattern where '*' matches any (possibly empty)
// run of characters, '/' included.
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case px < len(pattern) && pattern[px] == s[sx]:
			px++
			sx++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
