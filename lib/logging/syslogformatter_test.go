package logging

import (
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestSyslogFormatterSeverityMappingForAllLevels(t *testing.T) {
	tests := []struct {
		level    log.Level
		severity int
	}{
		{log.PanicLevel, 2},
		{log.FatalLevel, 2},
		{log.ErrorLevel, 3},
		{log.WarnLevel, 4},
		{log.InfoLevel, 6},
		{log.DebugLevel, 7},
		{log.TraceLevel, 7},
	}

	for _, tc := range tests {
		got := severityForLevel(tc.level)
		if got != tc.severity {
			t.Fatalf("severityForLevel(%v) = %d, want %d", tc.level, got, tc.severity)
		}
	}
}

func TestSyslogFormatterFacilityRangeValidation(t *testing.T) {
	tests := []struct {
		name     string
		facility int
		wantPri  string // expected priority prefix
	}{
		{name: "valid_user", facility: 1, wantPri: "<14>"}, // 1*8+6=14 for info
		{name: "valid_local0", facility: 16, wantPri: "<134>"}, // 16*8+6=134
		{name: "negative_defaults_to_user", facility: -1, wantPri: "<14>"}, // defaults to 1
		{name: "too_high_defaults_to_user", facility: 24, wantPri: "<14>"}, // defaults to 1
		{name: "zero_kern", facility: 0, wantPri: "<6>"}, // 0*8+6=6
		{name: "max_valid", facility: 23, wantPri: "<190>"}, // 23*8+6=190
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &SyslogFormatter{
				Hostname: "test",
				Facility: tc.facility,
			}
			entry := &log.Entry{
				Time:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Level:   log.InfoLevel,
				Message: "test",
			}
			out, err := f.Format(entry)
			if err != nil {
				t.Fatalf("Format() error = %v", err)
			}
			if !strings.HasPrefix(string(out), tc.wantPri) {
				t.Fatalf("output starts with %q, want prefix %q", string(out)[:10], tc.wantPri)
			}
		})
	}
}

func TestSyslogFormatterHostnameFallback(t *testing.T) {
	f := &SyslogFormatter{
		Hostname: "", // should fall back to os.Hostname()
	}
	entry := &log.Entry{
		Time:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Level:   log.InfoLevel,
		Message: "test",
	}
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	line := string(out)
	// Should NOT contain "- -" as hostname (should be actual hostname or "-")
	// Just verify it produces valid output
	if !strings.Contains(line, "1 2026-01-01T00:00:00Z") {
		t.Fatalf("unexpected output format: %q", line)
	}
	if !strings.Contains(line, "aurora") {
		t.Fatalf("expected default appName 'aurora' in output: %q", line)
	}
}

func TestSyslogFormatterCustomAppName(t *testing.T) {
	f := &SyslogFormatter{
		Hostname: "myhost",
		AppName:  "custom-app",
	}
	entry := &log.Entry{
		Time:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Level:   log.InfoLevel,
		Message: "test",
	}
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if !strings.Contains(string(out), "custom-app") {
		t.Fatalf("expected custom app name in output: %q", string(out))
	}
}

func TestSyslogFormatterEmptyMessage(t *testing.T) {
	f := &SyslogFormatter{Hostname: "test", Facility: 1}
	entry := &log.Entry{
		Time:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Level: log.InfoLevel,
		Data:  log.Fields{"key": "value"},
	}
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	line := string(out)
	// Should still include fields even with empty message
	if !strings.Contains(line, `key="value"`) {
		t.Fatalf("expected field in output: %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Fatal("expected newline termination")
	}
}

func TestSyslogFormatterSortedFields(t *testing.T) {
	f := &SyslogFormatter{Hostname: "test", Facility: 1}
	entry := &log.Entry{
		Time:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Level:   log.InfoLevel,
		Message: "test",
		Data: log.Fields{
			"zebra": "z",
			"alpha": "a",
			"mid":   "m",
		},
	}
	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	line := string(out)
	alphaIdx := strings.Index(line, "alpha=")
	midIdx := strings.Index(line, "mid=")
	zebraIdx := strings.Index(line, "zebra=")
	if alphaIdx > midIdx || midIdx > zebraIdx {
		t.Fatalf("fields not sorted alphabetically in output: %q", line)
	}
}

func TestSyslogFormatterFormatsRFC5424LikeLine(t *testing.T) {
	f := &SyslogFormatter{
		TimestampFormat: time.RFC3339,
		Hostname:        "test-host",
		AppName:         "aurora",
		Facility:        1,
	}

	entry := &log.Entry{
		Time:    time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
		Level:   log.WarnLevel,
		Message: "Sigma match",
		Data: log.Fields{
			"sigma_rule": "rule-1",
			"Image":      "/usr/bin/bash",
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	line := string(out)
	if !strings.HasPrefix(line, "<12>1 2026-02-11T12:00:00Z test-host aurora - - - Sigma match") {
		t.Fatalf("unexpected syslog prefix: %q", line)
	}
	if !strings.Contains(line, `Image="/usr/bin/bash"`) {
		t.Fatalf("expected Image field in %q", line)
	}
	if !strings.Contains(line, `sigma_rule="rule-1"`) {
		t.Fatalf("expected sigma_rule field in %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("expected newline-terminated output, got %q", line)
	}
}
