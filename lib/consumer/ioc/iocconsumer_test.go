package ioc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

func TestFilenameIOCFalsePositiveExclusionAndMatch(t *testing.T) {
	tmpDir := t.TempDir()
	filenameIOCPath := filepath.Join(tmpDir, "filename-iocs.txt")
	if err := os.WriteFile(filenameIOCPath, []byte(strings.Join([]string{
		"# comment",
		`(?i)\\procdump(64)?(a)?\.(exe|zip);50;(?i)(SysInternals\\)`,
		`(?i)\\evil\.exe;85`,
		`invalid-line-without-score`,
		`(invalid-regex;90`,
		"",
	}, "\n")), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	matchLogger, out := testLogger()
	consumer := New(Config{
		FilenameIOCPath:     filenameIOCPath,
		FilenameIOCRequired: true,
		Logger:              matchLogger,
	})
	if err := consumer.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	filteredEvent := &testEvent{
		id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 1},
		source: "LinuxEBPF:ProcessExec",
		ts:     time.Unix(1700000000, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"CommandLine": enrichment.NewStringValue(`C:\Tools\SysInternals\procdump64.exe`),
		},
	}
	if err := consumer.HandleEvent(filteredEvent); err != nil {
		t.Fatalf("HandleEvent(filteredEvent) error = %v", err)
	}

	matchedEvent := &testEvent{
		id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 11},
		source: "LinuxEBPF:FileCreate",
		ts:     time.Unix(1700000001, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"TargetFilename": enrichment.NewStringValue(`C:\Temp\evil.exe`),
		},
	}
	if err := consumer.HandleEvent(matchedEvent); err != nil {
		t.Fatalf("HandleEvent(matchedEvent) error = %v", err)
	}

	if got := consumer.Matches(); got != 1 {
		t.Fatalf("Matches() = %d, want 1", got)
	}

	lines := decodeJSONLines(t, out)
	if len(lines) != 1 {
		t.Fatalf("expected 1 IOC alert line, got %d", len(lines))
	}
	if got, _ := lines[0]["ioc_type"].(string); got != "filename" {
		t.Fatalf("ioc_type = %q, want filename", got)
	}
	if got, _ := lines[0]["ioc_field"].(string); got != "TargetFilename" {
		t.Fatalf("ioc_field = %q, want TargetFilename", got)
	}
	if got, _ := lines[0]["ioc_score"].(float64); int(got) != 85 {
		t.Fatalf("ioc_score = %v, want 85", lines[0]["ioc_score"])
	}
	if got, _ := lines[0]["level"].(string); got != "error" {
		t.Fatalf("level = %q, want error", got)
	}
}

func TestC2IOCMatchesNetworkFieldsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	c2IOCPath := filepath.Join(tmpDir, "c2-iocs.txt")
	if err := os.WriteFile(c2IOCPath, []byte(strings.Join([]string{
		"# comment",
		"example.com",
		"203.0.113.5",
		"bad line with spaces",
		"",
	}, "\n")), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	matchLogger, out := testLogger()
	consumer := New(Config{
		C2IOCPath:     c2IOCPath,
		C2IOCRequired: true,
		Logger:        matchLogger,
	})
	if err := consumer.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	commandLineOnly := &testEvent{
		id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 1},
		source: "LinuxEBPF:ProcessExec",
		ts:     time.Unix(1700000100, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"CommandLine": enrichment.NewStringValue("curl http://example.com/path"),
		},
	}
	if err := consumer.HandleEvent(commandLineOnly); err != nil {
		t.Fatalf("HandleEvent(commandLineOnly) error = %v", err)
	}

	hostMatch := &testEvent{
		id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 3},
		source: "LinuxEBPF:NetConnect",
		ts:     time.Unix(1700000101, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"DestinationHostname": enrichment.NewStringValue("ExAmPle.CoM."),
		},
	}
	if err := consumer.HandleEvent(hostMatch); err != nil {
		t.Fatalf("HandleEvent(hostMatch) error = %v", err)
	}

	ipMatch := &testEvent{
		id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 3},
		source: "LinuxEBPF:NetConnect",
		ts:     time.Unix(1700000102, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"DestinationIp": enrichment.NewStringValue("203.0.113.5"),
		},
	}
	if err := consumer.HandleEvent(ipMatch); err != nil {
		t.Fatalf("HandleEvent(ipMatch) error = %v", err)
	}

	if got := consumer.Matches(); got != 2 {
		t.Fatalf("Matches() = %d, want 2", got)
	}

	lines := decodeJSONLines(t, out)
	if len(lines) != 2 {
		t.Fatalf("expected 2 IOC alert lines, got %d", len(lines))
	}
	for i, line := range lines {
		if got, _ := line["ioc_type"].(string); got != "c2" {
			t.Fatalf("line %d ioc_type = %q, want c2", i, got)
		}
		if got, _ := line["ioc_field"].(string); got != "DestinationHostname" && got != "DestinationIp" {
			t.Fatalf("line %d ioc_field = %q, want network field", i, got)
		}
	}
}

func TestInitializeMissingRequiredIOCFileFails(t *testing.T) {
	consumer := New(Config{
		FilenameIOCPath:     "/definitely/missing/filename-iocs.txt",
		FilenameIOCRequired: true,
	})
	if err := consumer.Initialize(); err == nil {
		t.Fatal("Initialize() expected error for required missing IOC file")
	}
}

func TestInitializeMissingOptionalIOCFilesContinues(t *testing.T) {
	consumer := New(Config{})
	if err := consumer.Initialize(); err != nil {
		t.Fatalf("Initialize() unexpected error for optional missing IOC files: %v", err)
	}
}

type testEvent struct {
	id     provider.EventIdentifier
	pid    uint32
	source string
	ts     time.Time
	fields enrichment.DataFieldsMap
}

func (e *testEvent) ID() provider.EventIdentifier { return e.id }
func (e *testEvent) Process() uint32              { return e.pid }
func (e *testEvent) Source() string               { return e.source }
func (e *testEvent) Time() time.Time              { return e.ts }
func (e *testEvent) Value(fieldname string) enrichment.DataValue {
	return e.fields.Value(fieldname)
}
func (e *testEvent) ForEach(fn func(key string, value string)) { e.fields.ForEach(fn) }

func testLogger() (*log.Logger, *bytes.Buffer) {
	var out bytes.Buffer
	logger := log.New()
	logger.SetOutput(&out)
	logger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})
	return logger, &out
}

func decodeJSONLines(t *testing.T, out *bytes.Buffer) []map[string]interface{} {
	t.Helper()

	scanner := bufio.NewScanner(bytes.NewReader(out.Bytes()))
	lines := make([]map[string]interface{}, 0)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			t.Fatalf("json.Unmarshal() error = %v (line=%q)", err, raw)
		}
		lines = append(lines, payload)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner.Err() = %v", err)
	}
	return lines
}
