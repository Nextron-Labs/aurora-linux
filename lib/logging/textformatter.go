package logging

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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
	b.WriteString(entry.Message)

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
		if r < 0x20 || r == 0x7f || r == ' ' || r == '=' {
			return strconv.Quote(k)
		}
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
