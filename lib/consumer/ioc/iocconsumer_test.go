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
		`(?i)/procdump(64)?(a)?\.(exe|zip);50;(?i)(sysinternals/)`,
		`(?i)/evil\.exe;85`,
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
			"CommandLine": enrichment.NewStringValue(`/opt/sysinternals/procdump64.exe`),
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
			"TargetFilename": enrichment.NewStringValue(`/tmp/evil.exe`),
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
	if got, _ := lines[0]["ioc_level"].(string); got != "high" {
		t.Fatalf("ioc_level = %q, want high", got)
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
		// Entries without explicit score get defaultC2Score (80) → "high"
		if got, _ := line["ioc_level"].(string); got != "high" {
			t.Fatalf("line %d ioc_level = %q, want high", i, got)
		}
		if got, ok := line["ioc_score"].(float64); !ok || int(got) != defaultC2Score {
			t.Fatalf("line %d ioc_score = %v, want %d", i, line["ioc_score"], defaultC2Score)
		}
	}
}

func TestC2IOCWithScoreParsing(t *testing.T) {
	tmpDir := t.TempDir()
	c2IOCPath := filepath.Join(tmpDir, "c2-iocs.txt")
	if err := os.WriteFile(c2IOCPath, []byte(strings.Join([]string{
		"# C2 IOCs with scores",
		"high-severity.evil.com;95",
		"medium-severity.evil.com;65",
		"low-severity.evil.com;40",
		"no-score.evil.com",
		"10.0.0.1;90",
		"10.0.0.2;50",
		"10.0.0.3",
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

	tests := []struct {
		name      string
		field     string
		value     string
		wantScore int
		wantLevel string
		wantLog   string
	}{
		{"critical_domain", "DestinationHostname", "high-severity.evil.com", 95, "critical", "error"},
		{"medium_domain", "DestinationHostname", "medium-severity.evil.com", 65, "medium", "warning"},
		{"low_domain", "DestinationHostname", "low-severity.evil.com", 40, "low", "info"},
		{"default_domain", "DestinationHostname", "no-score.evil.com", defaultC2Score, "high", "error"},
		{"critical_ip", "DestinationIp", "10.0.0.1", 90, "critical", "error"},
		{"low_ip", "DestinationIp", "10.0.0.2", 50, "low", "info"},
		{"default_ip", "DestinationIp", "10.0.0.3", defaultC2Score, "high", "error"},
	}

	for _, tc := range tests {
		event := &testEvent{
			id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 3},
			source: "LinuxEBPF:NetConnect",
			ts:     time.Unix(1700000200, 0).UTC(),
			fields: enrichment.DataFieldsMap{
				tc.field: enrichment.NewStringValue(tc.value),
			},
		}
		if err := consumer.HandleEvent(event); err != nil {
			t.Fatalf("%s: HandleEvent() error = %v", tc.name, err)
		}
	}

	if got := consumer.Matches(); got != uint64(len(tests)) {
		t.Fatalf("Matches() = %d, want %d", got, len(tests))
	}

	lines := decodeJSONLines(t, out)
	if len(lines) != len(tests) {
		t.Fatalf("expected %d IOC alert lines, got %d", len(tests), len(lines))
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := lines[i]
			if got, _ := line["ioc_score"].(float64); int(got) != tc.wantScore {
				t.Fatalf("ioc_score = %v, want %d", line["ioc_score"], tc.wantScore)
			}
			if got, _ := line["ioc_level"].(string); got != tc.wantLevel {
				t.Fatalf("ioc_level = %q, want %q", got, tc.wantLevel)
			}
			if got, _ := line["level"].(string); got != tc.wantLog {
				t.Fatalf("level = %q, want %q", got, tc.wantLog)
			}
		})
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

func TestSanitizeFieldForLoggingRedactsSensitiveKeys(t *testing.T) {
	sensitiveKeys := []string{
		"password", "db_password", "ApiPassword",
		"token", "auth_token", "BearerToken",
		"secret", "client_secret", "SecretValue",
		"api_key", "apikey", "MyApiKey",
		"passwd",
	}
	for _, key := range sensitiveKeys {
		got := sanitizeFieldForLogging(key, "sensitive-value")
		if got != "[REDACTED]" {
			t.Fatalf("sanitizeFieldForLogging(%q, ...) = %q, want [REDACTED]", key, got)
		}
	}
}

func TestSanitizeFieldForLoggingPreservesNonSensitive(t *testing.T) {
	nonSensitive := []struct {
		key, value string
	}{
		{"Image", "/usr/bin/curl"},
		{"CommandLine", "ls -la"},
		{"User", "root"},
		{"ProcessId", "1234"},
	}
	for _, tc := range nonSensitive {
		got := sanitizeFieldForLogging(tc.key, tc.value)
		if got != tc.value {
			t.Fatalf("sanitizeFieldForLogging(%q, %q) = %q, want unchanged", tc.key, tc.value, got)
		}
	}
}

func TestSanitizeFieldForLoggingRedactsCommandLineSecrets(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		mustNotExist []string
		mustExist    []string
	}{
		{
			name:         "flag_password",
			input:        `curl --password hunter2 http://example.com`,
			mustNotExist: []string{"hunter2"},
			mustExist:    []string{"[REDACTED]", "curl", "example.com"},
		},
		{
			name:         "inline_token",
			input:        `token=abc123def456 cmd`,
			mustNotExist: []string{"abc123def456"},
			mustExist:    []string{"[REDACTED]"},
		},
		{
			name:         "multiple_secrets",
			input:        `app --password s3cr3t --token t0k3n`,
			mustNotExist: []string{"s3cr3t", "t0k3n"},
			mustExist:    []string{"[REDACTED]"},
		},
		{
			name:      "no_secrets",
			input:     `ls -la /tmp`,
			mustExist: []string{"ls -la /tmp"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeFieldForLogging("CommandLine", tc.input)
			for _, blocked := range tc.mustNotExist {
				if strings.Contains(got, blocked) {
					t.Fatalf("output %q still contains secret %q", got, blocked)
				}
			}
			for _, required := range tc.mustExist {
				if !strings.Contains(got, required) {
					t.Fatalf("output %q missing expected string %q", got, required)
				}
			}
		})
	}
}

func TestScoreToLevel(t *testing.T) {
	tests := []struct {
		score     int
		wantLevel log.Level
		wantName  string
	}{
		{100, log.ErrorLevel, "critical"},
		{95, log.ErrorLevel, "critical"},
		{90, log.ErrorLevel, "critical"},
		{89, log.ErrorLevel, "high"},
		{80, log.ErrorLevel, "high"},
		{75, log.ErrorLevel, "high"},
		{74, log.WarnLevel, "medium"},
		{70, log.WarnLevel, "medium"},
		{60, log.WarnLevel, "medium"},
		{59, log.InfoLevel, "low"},
		{50, log.InfoLevel, "low"},
		{40, log.InfoLevel, "low"},
		{39, log.InfoLevel, "info"},
		{20, log.InfoLevel, "info"},
		{0, log.InfoLevel, "info"},
		{-1, log.InfoLevel, "info"},
	}

	for _, tc := range tests {
		gotLevel, gotName := scoreToLevel(tc.score)
		if gotLevel != tc.wantLevel {
			t.Fatalf("scoreToLevel(%d) level = %v, want %v", tc.score, gotLevel, tc.wantLevel)
		}
		if gotName != tc.wantName {
			t.Fatalf("scoreToLevel(%d) name = %q, want %q", tc.score, gotName, tc.wantName)
		}
	}
}

func TestLogLevelForFilenameScoreBackwardsCompat(t *testing.T) {
	// logLevelForFilenameScore wraps scoreToLevel for backwards compatibility.
	// Verify it returns the same log.Level as scoreToLevel.
	scores := []int{100, 90, 80, 75, 74, 60, 50, 40, 39, 0, -1}
	for _, score := range scores {
		got := logLevelForFilenameScore(score)
		want, _ := scoreToLevel(score)
		if got != want {
			t.Fatalf("logLevelForFilenameScore(%d) = %v, want %v", score, got, want)
		}
	}
}

func TestIsLikelyDomainEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "valid", input: "evil.com", want: true},
		{name: "subdomain", input: "c2.evil.com", want: true},
		{name: "deeply_nested", input: "a.b.c.d.evil.com", want: true},
		{name: "with_dash", input: "my-evil-c2.example.com", want: true},
		{name: "with_numbers", input: "c2-123.evil.com", want: true},
		{name: "empty", input: "", want: false},
		{name: "leading_dot", input: ".evil.com", want: false},
		{name: "trailing_dot", input: "evil.com.", want: false},
		{name: "double_dot", input: "evil..com", want: false},
		{name: "no_dot", input: "localhost", want: false},
		{name: "single_char_tld", input: "a.b", want: true},
		{name: "uppercase_rejected", input: "Evil.com", want: false},
		{name: "underscore_rejected", input: "evil_host.com", want: false},
		{name: "space_rejected", input: "evil .com", want: false},
		{name: "unicode_rejected", input: "évil.com", want: false},
		{name: "just_dots", input: "...", want: false},
		{name: "single_dot", input: ".", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isLikelyDomain(tc.input)
			if got != tc.want {
				t.Fatalf("isLikelyDomain(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "ipv4", input: "192.168.1.1", want: "192.168.1.1"},
		{name: "ipv4_whitespace", input: "  10.0.0.1  ", want: "10.0.0.1"},
		{name: "ipv6_full", input: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", want: "2001:db8:85a3::8a2e:370:7334"},
		{name: "ipv6_short", input: "::1", want: "::1"},
		{name: "empty", input: "", want: ""},
		{name: "invalid", input: "not-an-ip", want: ""},
		{name: "domain", input: "example.com", want: ""},
		{name: "partial_ipv4", input: "192.168.1", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeIP(tc.input)
			if got != tc.want {
				t.Fatalf("normalizeIP(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Example.COM", "example.com"},
		{"  evil.COM.  ", "evil.com"},
		{"already-lower.test", "already-lower.test"},
		{"", ""},
		{"  ", ""},
	}

	for _, tc := range tests {
		got := normalizeDomain(tc.input)
		if got != tc.want {
			t.Fatalf("normalizeDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestLoadFilenameIOCsDuplicateDedup(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "dupes.txt")
	content := strings.Join([]string{
		`(?i)/evil\.exe;90`,
		`(?i)/evil\.exe;90`,
		`(?i)/evil\.exe;90`,
		`(?i)/other\.exe;80`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	entries, err := loadFilenameIOCs(path, true)
	if err != nil {
		t.Fatalf("loadFilenameIOCs() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after dedup, got %d", len(entries))
	}
}

func TestLoadFilenameIOCsSkipsMalformedLines(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "mixed.txt")
	content := strings.Join([]string{
		"# comment line",
		"",
		`no-score-field`,
		`(invalid-regex;90`,
		`;50`,
		`valid-pattern;not-a-number`,
		`(?i)/good\.exe;75`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	entries, err := loadFilenameIOCs(path, true)
	if err != nil {
		t.Fatalf("loadFilenameIOCs() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
	if entries[0].rawPattern != `(?i)/good\.exe` {
		t.Fatalf("pattern = %q, want (?i)/good\\.exe", entries[0].rawPattern)
	}
	if entries[0].score != 75 {
		t.Fatalf("score = %d, want 75", entries[0].score)
	}
}

func TestLoadFilenameIOCsEmptyPath(t *testing.T) {
	entries, err := loadFilenameIOCs("", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil for empty path, got %v", entries)
	}
}

func TestLoadC2IOCsCategorizesCorrectly(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "c2.txt")
	content := strings.Join([]string{
		"# C2 indicators",
		"evil-c2.example.com",
		"198.51.100.1",
		"203.0.113.42",
		"bad.domain.test",
		"10.0.0.1",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	domains, ips, err := loadC2IOCs(path, true)
	if err != nil {
		t.Fatalf("loadC2IOCs() error = %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d: %v", len(domains), domains)
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d: %v", len(ips), ips)
	}
	if _, ok := domains["evil-c2.example.com"]; !ok {
		t.Fatal("missing evil-c2.example.com")
	}
	if _, ok := ips["198.51.100.1"]; !ok {
		t.Fatal("missing 198.51.100.1")
	}
}

func TestLoadC2IOCsWithScores(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "c2.txt")
	content := strings.Join([]string{
		"# C2 with scores",
		"evil.com;95",
		"medium.com;65",
		"plain.com",
		"192.168.1.1;90",
		"10.0.0.1",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	domains, ips, err := loadC2IOCs(path, true)
	if err != nil {
		t.Fatalf("loadC2IOCs() error = %v", err)
	}

	// Check domain scores
	if entry, ok := domains["evil.com"]; !ok {
		t.Fatal("missing evil.com")
	} else if entry.score != 95 {
		t.Fatalf("evil.com score = %d, want 95", entry.score)
	}

	if entry, ok := domains["medium.com"]; !ok {
		t.Fatal("missing medium.com")
	} else if entry.score != 65 {
		t.Fatalf("medium.com score = %d, want 65", entry.score)
	}

	if entry, ok := domains["plain.com"]; !ok {
		t.Fatal("missing plain.com")
	} else if entry.score != defaultC2Score {
		t.Fatalf("plain.com score = %d, want %d (default)", entry.score, defaultC2Score)
	}

	// Check IP scores
	if entry, ok := ips["192.168.1.1"]; !ok {
		t.Fatal("missing 192.168.1.1")
	} else if entry.score != 90 {
		t.Fatalf("192.168.1.1 score = %d, want 90", entry.score)
	}

	if entry, ok := ips["10.0.0.1"]; !ok {
		t.Fatal("missing 10.0.0.1")
	} else if entry.score != defaultC2Score {
		t.Fatalf("10.0.0.1 score = %d, want %d (default)", entry.score, defaultC2Score)
	}
}

func TestLoadC2IOCsRejectsWhitespacedLines(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "c2.txt")
	content := "some invalid line with spaces\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	domains, ips, err := loadC2IOCs(path, true)
	if err != nil {
		t.Fatalf("loadC2IOCs() error = %v", err)
	}
	if len(domains) != 0 || len(ips) != 0 {
		t.Fatalf("expected 0 entries for whitespace lines, got domains=%d ips=%d", len(domains), len(ips))
	}
}

func TestMultipleFilenameIOCMatchesOnSingleEvent(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "filename-iocs.txt")
	content := strings.Join([]string{
		`(?i)/tmp/;50`,
		`(?i)evil;80`,
		`(?i)\.sh$;70`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	matchLogger, out := testLogger()
	consumer := New(Config{
		FilenameIOCPath:     path,
		FilenameIOCRequired: true,
		Logger:              matchLogger,
	})
	if err := consumer.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// This event matches ALL THREE patterns.
	event := &testEvent{
		id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 11},
		source: "LinuxEBPF:FileCreate",
		ts:     time.Unix(1700000000, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"TargetFilename": enrichment.NewStringValue("/tmp/evil.sh"),
		},
	}
	if err := consumer.HandleEvent(event); err != nil {
		t.Fatalf("HandleEvent() error = %v", err)
	}

	if got := consumer.Matches(); got != 3 {
		t.Fatalf("Matches() = %d, want 3 (one per matching pattern)", got)
	}

	lines := decodeJSONLines(t, out)
	if len(lines) != 3 {
		t.Fatalf("expected 3 IOC alert lines, got %d", len(lines))
	}

	// Verify ioc_level is present on all lines
	expectedLevels := []string{"low", "high", "medium"} // scores 50, 80, 70
	for i, line := range lines {
		if got, _ := line["ioc_level"].(string); got != expectedLevels[i] {
			t.Fatalf("line %d ioc_level = %q, want %q", i, got, expectedLevels[i])
		}
	}
}

func TestFilenameIOCLevelField(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "filename-iocs.txt")
	content := strings.Join([]string{
		`(?i)critical-tool;95`,
		`(?i)high-risk;80`,
		`(?i)medium-risk;65`,
		`(?i)low-risk;45`,
		`(?i)info-only;20`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	matchLogger, out := testLogger()
	consumer := New(Config{
		FilenameIOCPath:     path,
		FilenameIOCRequired: true,
		Logger:              matchLogger,
	})
	if err := consumer.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	tests := []struct {
		filename  string
		wantLevel string
		wantLog   string
	}{
		{"/tmp/critical-tool.exe", "critical", "error"},
		{"/tmp/high-risk.exe", "high", "error"},
		{"/tmp/medium-risk.exe", "medium", "warning"},
		{"/tmp/low-risk.exe", "low", "info"},
		{"/tmp/info-only.exe", "info", "info"},
	}

	for _, tc := range tests {
		event := &testEvent{
			id:     provider.EventIdentifier{ProviderName: "LinuxEBPF", EventID: 11},
			source: "LinuxEBPF:FileCreate",
			ts:     time.Unix(1700000000, 0).UTC(),
			fields: enrichment.DataFieldsMap{
				"TargetFilename": enrichment.NewStringValue(tc.filename),
			},
		}
		if err := consumer.HandleEvent(event); err != nil {
			t.Fatalf("HandleEvent(%s) error = %v", tc.filename, err)
		}
	}

	lines := decodeJSONLines(t, out)
	if len(lines) != len(tests) {
		t.Fatalf("expected %d lines, got %d", len(tests), len(lines))
	}

	for i, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {
			if got, _ := lines[i]["ioc_level"].(string); got != tc.wantLevel {
				t.Fatalf("ioc_level = %q, want %q", got, tc.wantLevel)
			}
			if got, _ := lines[i]["level"].(string); got != tc.wantLog {
				t.Fatalf("level = %q, want %q", got, tc.wantLog)
			}
		})
	}
}

// TestLoadC2IOCsRejectsMalformedEntries verifies that common formatting
// mistakes in C2 IOC files are rejected with warnings, not silently loaded.
func TestLoadC2IOCsRejectsMalformedEntries(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "c2.txt")
	content := strings.Join([]string{
		"# Malformed entries that must be rejected",
		"evildomain.com:65",        // colon instead of semicolon
		"bad:domain.com",           // colon in FQDN
		"192.168.1.1:8080",         // IP with port (colon)
		"evil domain.com",          // space in domain
		"not_a_domain",             // no dot, underscore
		";95",                      // empty indicator with score
		"evil.com;abc",             // non-numeric score — treated as full indicator, rejected by isLikelyDomain
		"",                         // empty line (skipped)
		"# Valid entries that must be accepted",
		"legit.evil.com;75",        // valid domain with score
		"clean-c2.example.org",     // valid domain without score
		"10.20.30.40;60",           // valid IP with score
		"172.16.0.1",               // valid IP without score
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	domains, ips, err := loadC2IOCs(path, true)
	if err != nil {
		t.Fatalf("loadC2IOCs() error = %v", err)
	}

	// Exactly 2 valid domains should load
	if len(domains) != 2 {
		t.Fatalf("expected 2 valid domains, got %d: %v", len(domains), domains)
	}
	if _, ok := domains["legit.evil.com"]; !ok {
		t.Error("missing legit.evil.com")
	}
	if _, ok := domains["clean-c2.example.org"]; !ok {
		t.Error("missing clean-c2.example.org")
	}

	// Exactly 2 valid IPs should load
	if len(ips) != 2 {
		t.Fatalf("expected 2 valid IPs, got %d: %v", len(ips), ips)
	}
	if entry, ok := ips["10.20.30.40"]; !ok {
		t.Error("missing 10.20.30.40")
	} else if entry.score != 60 {
		t.Errorf("10.20.30.40 score = %d, want 60", entry.score)
	}
	if entry, ok := ips["172.16.0.1"]; !ok {
		t.Error("missing 172.16.0.1")
	} else if entry.score != defaultC2Score {
		t.Errorf("172.16.0.1 score = %d, want %d (default)", entry.score, defaultC2Score)
	}

	// Verify scores on domains
	if entry := domains["legit.evil.com"]; entry.score != 75 {
		t.Errorf("legit.evil.com score = %d, want 75", entry.score)
	}
	if entry := domains["clean-c2.example.org"]; entry.score != defaultC2Score {
		t.Errorf("clean-c2.example.org score = %d, want %d (default)", entry.score, defaultC2Score)
	}
}

// TestLoadFilenameIOCsThreeFieldFormat verifies the REGEX;SCORE;FP_REGEX format
// including edge cases with false-positive exclusion patterns.
func TestLoadFilenameIOCsThreeFieldFormat(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "filename-iocs.txt")
	content := strings.Join([]string{
		// Standard two-field
		`\\evil\.exe;80`,
		// Three-field with FP exclusion
		`\\cmd\.exe;65;\\(System32|Winsxs)\\`,
		// Three-field with empty FP field (should work, no FP filter)
		`\\danger\.dll;90;`,
		// Missing leading backslash (still valid regex, just broader match)
		`master\.exe;70`,
		// Properly escaped leading backslash
		`\\\\master\.exe;70`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	entries, err := loadFilenameIOCs(path, true)
	if err != nil {
		t.Fatalf("loadFilenameIOCs() error = %v", err)
	}

	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}

	// Verify the three-field entry has a compiled FP exclusion
	cmdEntry := entries[1] // \\cmd\.exe;65;\\(System32|Winsxs)\\
	if cmdEntry.score != 65 {
		t.Errorf("cmd.exe score = %d, want 65", cmdEntry.score)
	}
	if cmdEntry.falsePositive == nil {
		t.Fatal("cmd.exe should have a false-positive exclusion pattern")
	}
	// FP pattern should match System32 paths
	if !cmdEntry.falsePositive.MatchString(`C:\Windows\System32\cmd.exe`) {
		t.Error("FP pattern should match System32 path")
	}
	// But not match other paths
	if cmdEntry.falsePositive.MatchString(`C:\Temp\cmd.exe`) {
		t.Error("FP pattern should NOT match Temp path")
	}

	// Empty FP field should result in nil falsePositive
	dangerEntry := entries[2]
	if dangerEntry.falsePositive != nil {
		t.Error("empty FP field should result in nil falsePositive")
	}
	if dangerEntry.score != 90 {
		t.Errorf("danger.dll score = %d, want 90", dangerEntry.score)
	}
}

// TestLoadFilenameIOCsRejectsMalformedEntries tests that invalid filename IOC
// lines are rejected — missing score, invalid regex, non-numeric score.
func TestLoadFilenameIOCsRejectsMalformedEntries(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "filename-iocs.txt")
	content := strings.Join([]string{
		`no-score-field`,
		`(invalid-regex;90`,
		`;50`,
		`valid-pattern;not-a-num`,
		`good\.exe;abc;fp-pattern`,
		`ok\.dll;75;(unclosed`,
		"# this is a comment line",
		``,
		`(?i)\\legit\.exe;80`,      // valid entry
		`(?i)\\tool\.exe;60;(?i)\\Windows\\`, // valid three-field
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	entries, err := loadFilenameIOCs(path, true)
	if err != nil {
		t.Fatalf("loadFilenameIOCs() error = %v", err)
	}

	// Only the 2 valid entries should load
	if len(entries) != 2 {
		for i, e := range entries {
			t.Logf("  entry[%d]: pattern=%q score=%d", i, e.rawPattern, e.score)
		}
		t.Fatalf("expected 2 valid entries, got %d", len(entries))
	}

	if entries[0].rawPattern != `(?i)\\legit\.exe` || entries[0].score != 80 {
		t.Errorf("entry[0] = %q;%d, want (?i)\\\\legit\\.exe;80", entries[0].rawPattern, entries[0].score)
	}
	if entries[1].rawPattern != `(?i)\\tool\.exe` || entries[1].score != 60 || entries[1].falsePositive == nil {
		t.Errorf("entry[1] unexpected: pattern=%q score=%d hasFP=%v", entries[1].rawPattern, entries[1].score, entries[1].falsePositive != nil)
	}
}

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
