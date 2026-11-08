package logging

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestJSONFormatterBasicOutput(t *testing.T) {
	f := &JSONFormatter{}
	entry := &log.Entry{
		Time:    time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Level:   log.WarnLevel,
		Message: "Sigma match",
		Data: log.Fields{
			"Image": "/usr/bin/bash",
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got, _ := m["message"].(string); got != "Sigma match" {
		t.Fatalf("message = %q, want Sigma match", got)
	}
	if got, _ := m["level"].(string); got != "warning" {
		t.Fatalf("level = %q, want warning", got)
	}
	if got, _ := m["Image"].(string); got != "/usr/bin/bash" {
		t.Fatalf("Image = %q, want /usr/bin/bash", got)
	}
	if _, ok := m["timestamp"]; !ok {
		t.Fatal("timestamp missing")
	}
	if !strings.HasSuffix(string(out), "\n") {
		t.Fatal("expected newline-terminated output")
	}
}

func TestJSONFormatterCustomTimestampFormat(t *testing.T) {
	f := &JSONFormatter{TimestampFormat: time.RFC3339}
	entry := &log.Entry{
		Time:    time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC),
		Level:   log.InfoLevel,
		Message: "test",
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(out, &m)

	ts, _ := m["timestamp"].(string)
	if ts != "2026-01-15T08:30:00Z" {
		t.Fatalf("timestamp = %q, want RFC3339 format", ts)
	}
}

func TestJSONFormatterDefaultTimestampIsRFC3339Nano(t *testing.T) {
	f := &JSONFormatter{} // no custom format
	entry := &log.Entry{
		Time:    time.Date(2026, 6, 1, 12, 0, 0, 123456789, time.UTC),
		Level:   log.InfoLevel,
		Message: "nano test",
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(out, &m)
	ts, _ := m["timestamp"].(string)
	// RFC3339Nano should include nanoseconds
	if !strings.Contains(ts, ".123456789") {
		t.Fatalf("timestamp = %q, expected nanosecond precision", ts)
	}
}

func TestJSONFormatterEmptyMessage(t *testing.T) {
	f := &JSONFormatter{}
	entry := &log.Entry{
		Time:  time.Unix(0, 0).UTC(),
		Level: log.ErrorLevel,
		Data:  log.Fields{"key": "value"},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(out, &m)
	if _, exists := m["message"]; exists {
		t.Fatalf("empty message should be omitted, got %v", m["message"])
	}
	if got, _ := m["level"].(string); got != "error" {
		t.Fatalf("level = %q, want error", got)
	}
}

func TestJSONFormatterSpecialCharacters(t *testing.T) {
	f := &JSONFormatter{}
	entry := &log.Entry{
		Time:    time.Unix(0, 0).UTC(),
		Level:   log.WarnLevel,
		Message: "match",
		Data: log.Fields{
			"CommandLine": `echo "hello\nworld" && curl http://evil.test`,
			"unicode":     "日本語テスト",
			"quotes":      `value with "quotes" and 'apostrophes'`,
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output not valid JSON after special chars: %v\nraw: %s", err, out)
	}
	if got, _ := m["unicode"].(string); got != "日本語テスト" {
		t.Fatalf("unicode field = %q, want 日本語テスト", got)
	}
}

func TestJSONFormatterAllLogLevels(t *testing.T) {
	f := &JSONFormatter{}
	levels := []log.Level{
		log.TraceLevel, log.DebugLevel, log.InfoLevel,
		log.WarnLevel, log.ErrorLevel,
	}

	for _, level := range levels {
		entry := &log.Entry{
			Time:    time.Unix(0, 0).UTC(),
			Level:   level,
			Message: "test",
		}
		out, err := f.Format(entry)
		if err != nil {
			t.Fatalf("Format() at level %v error = %v", level, err)
		}

		var m map[string]interface{}
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("invalid JSON at level %v: %v", level, err)
		}
		if got, _ := m["level"].(string); got != level.String() {
			t.Fatalf("level = %q, want %q", got, level.String())
		}
	}
}
