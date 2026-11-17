package logging

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

// TextFormatter formats log entries as human-readable single-line text.
type TextFormatter struct {
	TimestampFormat string
}

// Format renders a log entry as a text line.
func (f *TextFormatter) Format(entry *log.Entry) ([]byte, error) {
	var b strings.Builder

	tsFormat := f.TimestampFormat
	if tsFormat == "" {
		tsFormat = time.RFC3339
	}

	b.WriteString(entry.Time.Format(tsFormat))
	b.WriteString(" ")
	b.WriteString(strings.ToUpper(entry.Level.String()))
	b.WriteString(" ")
	b.WriteString(sanitizeMessage(entry.Message))

	// Sort field keys for consistent output
	keys := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := entry.Data[k]
		b.WriteString(fmt.Sprintf(" %s=%s", formatTextFieldKey(k), formatTextFieldValue(v)))
	}
	b.WriteString("\n")

	return []byte(b.String()), nil
}

func formatTextFieldKey(k string) string {
	for _, r := range k {
		if unsafeRune(r) || r == ' ' || r == '=' || r == '"' || r >= 0x80 {
			return strconv.Quote(k)
		}
	}
	if !utf8.ValidString(k) {
		return strconv.Quote(k)
	}
	return k
}

func formatTextFieldValue(v interface{}) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case fmt.Stringer:
		return strconv.Quote(x.String())
	default:
		return fmt.Sprint(v)
	}
}

// sanitizeMessage neutralises characters in the free-text log message that
// could forge log lines or mislead a reader: C0/C1 controls, DEL, Unicode
// line/paragraph separators and bidirectional overrides. Invalid UTF-8 is
// replaced.
func sanitizeMessage(m string) string {
	if !utf8.ValidString(m) {
		m = strings.ToValidUTF8(m, "\uFFFD")
	}
	clean := true
	for _, r := range m {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return m
	}
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return ' '
		}
		return r
	}, m)
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f: // C0, DEL, C1
		return true
	case r == 0x2028 || r == 0x2029: // line / paragraph separator
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f: // bidi
		return true
	}
	return false
}
