// Package syslog is an optional input provider that tails syslog-style log
// files (and optionally the systemd journal) and turns every line into an
// event for the Sigma linux syslog/auth/sshd/cron/... rules.
package syslog

import (
	"regexp"
	"strconv"
	"strings"
)

// Parsed is a decoded syslog line.
type Parsed struct {
	Hostname string
	Program  string
	PID      string
	Message  string
	Facility string
	Severity string
}

var (
	// <34>1 2026-11-09T10:00:00Z host app 123 ID47 [sd] message
	rfc5424 = regexp.MustCompile(`^(?:<(\d{1,3})>)?1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+) ?(.*)$`)
	// Nov  9 10:00:00 host prog[123]: message   (also ISO timestamps)
	rfc3164 = regexp.MustCompile(`^(?:<(\d{1,3})>)?(?:[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) (\S+) (.*)$`)
	tagRe   = regexp.MustCompile(`^([^\s:\[\]]+)(?:\[(\d+)\])?:? ?(.*)$`)
)

var facilityNames = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
	"authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

var severityNames = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

func applyPri(p *Parsed, pri string) {
	n, err := strconv.Atoi(pri)
	if pri == "" || err != nil {
		return
	}
	if f := n >> 3; f < len(facilityNames) {
		p.Facility = facilityNames[f]
	}
	p.Severity = severityNames[n&7]
}

// ParseLine decodes RFC 5424 and RFC 3164 lines. Anything else is returned
// as a bare message so keyword rules still see it.
func ParseLine(line string) Parsed {
	line = strings.TrimRight(line, "\r\n")
	var p Parsed

	if m := rfc5424.FindStringSubmatch(line); m != nil {
		applyPri(&p, m[1])
		p.Hostname = nilToEmpty(m[3])
		p.Program = nilToEmpty(m[4])
		p.PID = nilToEmpty(m[5])
		p.Message = m[8]
		return p
	}
	if m := rfc3164.FindStringSubmatch(line); m != nil {
		applyPri(&p, m[1])
		p.Hostname = m[2]
		rest := m[3]
		if t := tagRe.FindStringSubmatch(rest); t != nil && looksLikeTag(rest, t) {
			p.Program, p.PID, p.Message = t[1], t[2], t[3]
		} else {
			p.Message = rest
		}
		return p
	}
	p.Message = line
	return p
}

// looksLikeTag accepts "prog:" / "prog[pid]:" and rejects free text whose
// first word merely happens to precede a colon far away.
func looksLikeTag(rest string, t []string) bool {
	head := rest
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		head = rest[:i]
	}
	return strings.HasSuffix(head, ":") || t[2] != ""
}

func nilToEmpty(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// programServices maps a program name to Sigma logsource services besides the
// generic "syslog".
var programServices = map[string][]string{
	"sshd":           {"sshd", "auth"},
	"sshd-session":   {"sshd", "auth"}, // OpenSSH 9.8+
	"sshd-auth":      {"sshd", "auth"},
	"pkexec":         {"auth"},
	"unix_chkpwd":    {"auth"},
	"systemd-logind": {"auth"},
	"gdm-password":   {"auth"},
	"sudo":           {"sudo", "auth"},
	"su":             {"su", "auth"},
	"login":          {"auth"},
	"passwd":         {"auth"},
	"useradd":        {"auth"},
	"usermod":        {"auth"},
	"groupadd":       {"auth"},
	"polkitd":        {"auth"},
	"cron":           {"cron"},
	"crond":          {"cron"},
	"crontab":        {"cron"},
	"anacron":        {"cron"},
	"vsftpd":         {"vsftpd"},
	"clamd":          {"clamav"},
	"freshclam":      {"clamav"},
	"clamav":         {"clamav"},
	"guacd":          {"guacamole"},
	"guacamole":      {"guacamole"},
}

// AllServices is every Sigma logsource service the provider can feed.
var AllServices = []string{
	"syslog", "auth", "sshd", "sudo", "su", "cron", "vsftpd", "clamav", "guacamole",
}

// ServicesFor returns the logsource services of a log line from program
// (and its syslog facility, if known).
func ServicesFor(program, facility string) []string {
	base := strings.ToLower(program)
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	// "CRON" (Debian) and "cron" are the same daemon.
	out := []string{"syslog"}
	out = append(out, programServices[base]...)
	if facility == "auth" || facility == "authpriv" {
		has := false
		for _, s := range out {
			has = has || s == "auth"
		}
		if !has {
			out = append(out, "auth")
		}
	}
	return out
}
