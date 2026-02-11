package logging

import (
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

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
