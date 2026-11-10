package logging

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// SyslogFormatter formats log entries as RFC5424-like syslog lines.
type SyslogFormatter struct {
	TimestampFormat string
	Hostname        string
	AppName         string
	Facility        int
}

// Format renders a log entry as a single syslog line.
func (f *SyslogFormatter) Format(entry *log.Entry) ([]byte, error) {
	tsFormat := f.TimestampFormat
	if tsFormat == "" {
		tsFormat = time.RFC3339
	}

	hostname := strings.TrimSpace(f.Hostname)
	if hostname == "" {
		if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
			hostname = strings.TrimSpace(h)
		} else {
			hostname = "-"
		}
	}

	appName := strings.TrimSpace(f.AppName)
	if appName == "" {
		appName = "aurora"
	}

	facility := f.Facility
	if facility < 0 || facility > 23 {
		facility = 1 // user-level messages
	}
	priority := facility*8 + severityForLevel(entry.Level)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("<%d>1 %s %s %s - - -", priority, entry.Time.Format(tsFormat), hostname, appName))

	if entry.Message != "" {
		b.WriteString(" ")
		b.WriteString(sanitizeMessage(entry.Message))
	}

	keys := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(" ")
		b.WriteString(formatTextFieldKey(k))
		b.WriteString("=")
		b.WriteString(formatTextFieldValue(entry.Data[k]))
	}
	b.WriteString("\n")

	return []byte(b.String()), nil
}

func severityForLevel(level log.Level) int {
	switch level {
	case log.PanicLevel, log.FatalLevel:
		return 2
	case log.ErrorLevel:
		return 3
	case log.WarnLevel:
		return 4
	case log.InfoLevel:
		return 6
	case log.DebugLevel, log.TraceLevel:
		return 7
	default:
		return 6
	}
}
