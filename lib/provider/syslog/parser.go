package syslog

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// syslogLine is the parsed representation of a single syslog file line.
// All fields are best-effort: a malformed line still yields a syslogLine
// with at least Raw and Message populated so that keyword matching works.
type syslogLine struct {
	Timestamp time.Time
	Host      string
	Program   string
	PID       uint32
	Message   string
	Raw       string
}

var (
	// ISO 8601 / RFC5424-ish prefix used by modern rsyslog / journald
	// forwarding: "2026-04-30T03:16:46.845745+00:00 host program[pid]: msg"
	isoSyslogRegex = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^\[: ]+)(?:\[(\d+)\])?:\s*(.*)$`,
	)
	// RFC3164 (BSD-style): "Apr 30 03:16:46 host program[pid]: msg".
	rfc3164Regex = regexp.MustCompile(
		`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[: ]+)(?:\[(\d+)\])?:\s*(.*)$`,
	)
	// Optional <PRI> prefix at the very start of an RFC5424 line.
	priPrefixRegex = regexp.MustCompile(`^<\d{1,3}>\d?\s*`)

	isoLayouts = []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05.999999-07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05.999999999Z",
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05Z",
	}
)

// parseLine parses a syslog line. Returns nil for an empty line. A line
// that doesn't match any known format is still returned with Raw/Message
// set so keyword-based sigma rules still get a chance to match.
func parseLine(raw string) *syslogLine {
	line := strings.TrimRight(raw, "\r\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	body := priPrefixRegex.ReplaceAllString(line, "")

	if m := isoSyslogRegex.FindStringSubmatch(body); m != nil {
		ts, _ := parseISOTimestamp(m[1])
		return &syslogLine{
			Timestamp: ts,
			Host:      m[2],
			Program:   m[3],
			PID:       parsePID(m[4]),
			Message:   m[5],
			Raw:       line,
		}
	}
	if m := rfc3164Regex.FindStringSubmatch(body); m != nil {
		ts, _ := parseRFC3164Timestamp(m[1])
		return &syslogLine{
			Timestamp: ts,
			Host:      m[2],
			Program:   m[3],
			PID:       parsePID(m[4]),
			Message:   m[5],
			Raw:       line,
		}
	}

	return &syslogLine{
		Timestamp: time.Now(),
		Message:   body,
		Raw:       line,
	}
}

func parseISOTimestamp(s string) (time.Time, error) {
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Now(), errors.New("unrecognized iso timestamp")
}

// parseRFC3164Timestamp parses "Jan _2 15:04:05" into a time.Time. RFC3164
// omits the year so the current year is assumed; if that places the entry
// more than a day in the future we roll back to the previous year.
func parseRFC3164Timestamp(s string) (time.Time, error) {
	t, err := time.Parse("Jan _2 15:04:05", s)
	if err != nil {
		return time.Now(), err
	}
	now := time.Now()
	parsed := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
	if parsed.Sub(now) > 24*time.Hour {
		parsed = parsed.AddDate(-1, 0, 0)
	}
	return parsed, nil
}

func parsePID(s string) uint32 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
