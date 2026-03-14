package logging

import (
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestTextFormatterBasicFormat(t *testing.T) {
	f := &TextFormatter{TimestampFormat: time.RFC3339}
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
	s := string(out)

	if !strings.HasPrefix(s, "2026-03-14T12:00:00Z") {
		t.Fatalf("expected timestamp prefix, got %q", s)
	}
	if !strings.Contains(s, "WARNING") {
		t.Fatalf("expected uppercase level, got %q", s)
	}
	if !strings.Contains(s, "Sigma match") {
		t.Fatalf("expected message in output, got %q", s)
	}
	if !strings.Contains(s, `Image="/usr/bin/bash"`) {
		t.Fatalf("expected field in output, got %q", s)
	}
	if !strings.HasSuffix(s, "\n") {
		t.Fatal("expected newline-terminated output")
	}
}

func TestTextFormatterDefaultTimestamp(t *testing.T) {
	f := &TextFormatter{} // empty TimestampFormat should default to RFC3339
	entry := &log.Entry{
		Time:    time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC),
		Level:   log.InfoLevel,
		Message: "test",
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if !strings.HasPrefix(string(out), "2026-06-15T09:00:00Z") {
		t.Fatalf("expected RFC3339 default timestamp, got %q", string(out))
	}
}

func TestTextFormatterEmptyMessage(t *testing.T) {
	f := &TextFormatter{TimestampFormat: time.RFC3339}
	entry := &log.Entry{
		Time:  time.Unix(0, 0).UTC(),
		Level: log.InfoLevel,
		Data:  log.Fields{"key": "value"},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `key="value"`) {
		t.Fatalf("expected field even with empty message, got %q", s)
	}
}

func TestTextFormatterSortedFields(t *testing.T) {
	f := &TextFormatter{TimestampFormat: time.RFC3339}
	entry := &log.Entry{
		Time:    time.Unix(0, 0).UTC(),
		Level:   log.InfoLevel,
		Message: "test",
		Data: log.Fields{
			"zebra": "z",
			"alpha": "a",
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	s := string(out)
	alphaIdx := strings.Index(s, "alpha=")
	zebraIdx := strings.Index(s, "zebra=")
	if alphaIdx > zebraIdx {
		t.Fatalf("fields not sorted: %q", s)
	}
}

func TestTextFormatterNumericFieldValues(t *testing.T) {
	f := &TextFormatter{TimestampFormat: time.RFC3339}
	entry := &log.Entry{
		Time:    time.Unix(0, 0).UTC(),
		Level:   log.InfoLevel,
		Message: "test",
		Data: log.Fields{
			"score": 95,
			"rate":  3.14,
			"flag":  true,
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	s := string(out)
	// Numeric values should not be quoted
	if !strings.Contains(s, "score=95") {
		t.Fatalf("expected unquoted int in output, got %q", s)
	}
	if !strings.Contains(s, "flag=true") {
		t.Fatalf("expected unquoted bool in output, got %q", s)
	}
}

func TestTextFormatterEscapesStringFields(t *testing.T) {
	f := &TextFormatter{TimestampFormat: time.RFC3339}
	entry := &log.Entry{
		Time:    time.Unix(0, 0).UTC(),
		Level:   log.WarnLevel,
		Message: "Sigma match",
		Data: log.Fields{
			"CommandLine": "echo hi\nforged=1",
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	s := string(out)
	if strings.Contains(s, "forged=1\n") {
		t.Fatalf("unexpected unescaped newline injection in output: %q", s)
	}
	if !strings.Contains(s, `CommandLine="echo hi\nforged=1"`) {
		t.Fatalf("expected escaped command line field in output, got %q", s)
	}
}

func TestTextFormatterEscapesUnsafeFieldKeys(t *testing.T) {
	f := &TextFormatter{TimestampFormat: time.RFC3339}
	entry := &log.Entry{
		Time:    time.Unix(0, 0).UTC(),
		Level:   log.InfoLevel,
		Message: "test",
		Data: log.Fields{
			"bad key=\n": "value",
		},
	}

	out, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	s := string(out)
	if strings.Contains(s, "bad key=\n") {
		t.Fatalf("unsafe field key was not escaped: %q", s)
	}
	if !strings.Contains(s, `"bad key=\n"="value"`) {
		t.Fatalf("expected escaped key/value in output, got %q", s)
	}
}
