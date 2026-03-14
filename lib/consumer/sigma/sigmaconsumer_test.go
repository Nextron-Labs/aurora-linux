package sigma

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	sigmaengine "github.com/markuskont/go-sigma-rule-engine"
	"github.com/nicholasgasior/aurora-linux/lib/enrichment"
	"github.com/nicholasgasior/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

func TestAllowMatchDisabledThrottleAllowsAll(t *testing.T) {
	consumer := New(Config{
		ThrottleRate:  0,
		ThrottleBurst: 1,
	})

	for i := 0; i < 10; i++ {
		if !consumer.allowMatch("rule-1") {
			t.Fatalf("allowMatch() denied match %d with throttle disabled", i+1)
		}
	}
}

func TestAllowMatchEnabledThrottleLimitsBurst(t *testing.T) {
	consumer := New(Config{
		ThrottleRate:  0.001,
		ThrottleBurst: 1,
	})

	if !consumer.allowMatch("rule-1") {
		t.Fatal("first match should be allowed")
	}
	if consumer.allowMatch("rule-1") {
		t.Fatal("second immediate match should be throttled")
	}
}

func TestAllowMatchPerRuleIsolation(t *testing.T) {
	consumer := New(Config{
		ThrottleRate:  0.001, // very slow refill
		ThrottleBurst: 1,
	})

	// Rule-A uses its burst.
	if !consumer.allowMatch("rule-A") {
		t.Fatal("rule-A first match should be allowed")
	}
	if consumer.allowMatch("rule-A") {
		t.Fatal("rule-A second match should be throttled")
	}

	// Rule-B should have its own separate limiter.
	if !consumer.allowMatch("rule-B") {
		t.Fatal("rule-B first match should be allowed (independent of rule-A)")
	}
	if consumer.allowMatch("rule-B") {
		t.Fatal("rule-B second match should be throttled")
	}
}

func TestAllowMatchBurstSizeRespected(t *testing.T) {
	consumer := New(Config{
		ThrottleRate:  0.001, // very slow refill
		ThrottleBurst: 3,
	})

	// Should allow exactly 3 matches in burst.
	for i := 0; i < 3; i++ {
		if !consumer.allowMatch("rule-1") {
			t.Fatalf("match %d should be allowed within burst of 3", i+1)
		}
	}
	// 4th should be throttled.
	if consumer.allowMatch("rule-1") {
		t.Fatal("4th match should be throttled (burst=3)")
	}
}

func TestAllowMatchDefaultBurstWhenNotSet(t *testing.T) {
	consumer := New(Config{
		ThrottleRate:  1.0,
		ThrottleBurst: 0, // should default to 5
	})

	if consumer.throttleBurst != 5 {
		t.Fatalf("default burst = %d, want 5", consumer.throttleBurst)
	}
}

func TestInitializeWithRulesFailsWhenNoRulesAreLoadable(t *testing.T) {
	ruleDir := t.TempDir()
	badRulePath := filepath.Join(ruleDir, "bad.yml")
	if err := os.WriteFile(badRulePath, []byte("title: [broken"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	consumer := New(Config{})
	err := consumer.InitializeWithRules([]string{ruleDir})
	if err == nil {
		t.Fatal("InitializeWithRules() expected error when no rules are loadable")
	}
	if !strings.Contains(err.Error(), "no loadable Sigma rules") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitializeWithRulesAppliesMinLevelFilter(t *testing.T) {
	ruleDir := t.TempDir()
	const lowID = "11111111-1111-1111-1111-111111111111"
	const highID = "22222222-2222-2222-2222-222222222222"

	writeRuleFile(t, ruleDir, "low.yml", fmt.Sprintf(`title: Low Rule
id: %s
status: test
author: unit
level: low
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: "/lowbin"
  condition: selection
`, lowID))
	writeRuleFile(t, ruleDir, "high.yml", fmt.Sprintf(`title: High Rule
id: %s
status: test
author: unit
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: "/highbin"
  condition: selection
`, highID))

	consumer := New(Config{MinLevel: "medium"})
	if err := consumer.InitializeWithRules([]string{ruleDir}); err != nil {
		t.Fatalf("InitializeWithRules() error = %v", err)
	}

	if got := len(consumer.ruleset.Rules); got != 1 {
		t.Fatalf("expected 1 loaded rule after --min-level filtering, got %d", got)
	}
	if got := consumer.lookupRuleLevel(lowID); got != "" {
		t.Fatalf("low-level rule should be filtered out, lookupRuleLevel() = %q", got)
	}
	if got := consumer.lookupRuleLevel(highID); got != "high" {
		t.Fatalf("expected high-level rule, got %q", got)
	}

	results := consumer.EvalFieldsMap(map[string]string{
		"Image": "/usr/bin/highbin",
	})
	if len(results) != 1 {
		t.Fatalf("expected 1 match after filtering, got %d", len(results))
	}
	if results[0].ID != highID {
		t.Fatalf("expected high rule ID, got %q", results[0].ID)
	}
}

func TestEmitMatchDoesNotAllowReservedFieldOverride(t *testing.T) {
	var out bytes.Buffer
	logger := log.New()
	logger.SetOutput(&out)
	logger.SetFormatter(&log.JSONFormatter{
		DisableTimestamp:  true,
		DisableHTMLEscape: true,
	})

	consumer := New(Config{Logger: logger})
	event := &testEvent{
		ts: time.Unix(1700000000, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"sigma_rule": enrichment.NewStringValue("attacker-rule"),
			"timestamp":  enrichment.NewStringValue("attacker-ts"),
			"ApiToken":   enrichment.NewStringValue("super-secret-token"),
			"CommandLine": enrichment.NewStringValue(
				`curl --password hunter2 --token abc123 --url http://example.test`,
			),
			"Image": enrichment.NewStringValue("/bin/bash"),
		},
	}

	consumer.emitMatch(event, sigmaengine.Result{
		ID:    "real-rule",
		Title: "Real Rule",
	})

	var logged map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &logged); err != nil {
		t.Fatalf("failed to decode logged JSON: %v", err)
	}

	if got, _ := logged["sigma_rule"].(string); got != "real-rule" {
		t.Fatalf("sigma_rule override detected, got %q", got)
	}
	if got, _ := logged["event_sigma_rule"].(string); got != "attacker-rule" {
		t.Fatalf("expected attacker field to be namespaced, got %q", got)
	}
	if got, _ := logged["event_timestamp"].(string); got != "attacker-ts" {
		t.Fatalf("expected colliding timestamp to be namespaced, got %q", got)
	}
	if got, _ := logged["ApiToken"].(string); got != "[REDACTED]" {
		t.Fatalf("expected sensitive field redaction, got %q", got)
	}
	if got, _ := logged["CommandLine"].(string); strings.Contains(got, "hunter2") || strings.Contains(got, "abc123") {
		t.Fatalf("expected command-line secret redaction, got %q", got)
	}
}

func TestHandleEventIncludesRuleMetadataAndMatchEvidence(t *testing.T) {
	ruleDir := t.TempDir()
	const ruleID = "c248c896-e412-4279-8c15-1c558067b6fa"

	writeRuleFile(t, ruleDir, "whoami_all.yml", fmt.Sprintf(`title: Enumerate All Information With Whoami.EXE
id: %s
status: experimental
description: Detects the execution of "whoami.exe" with the "/all" flag
author: Unit Tester
date: 2026-02-01
modified: 2026-02-02
references:
  - https://example.com/reference
falsepositives:
  - Unknown
tags:
  - attack.discovery
  - attack.t1033
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: "/whoami"
    CommandLine|contains: " /all"
  condition: selection
`, ruleID))

	var out bytes.Buffer
	logger := log.New()
	logger.SetOutput(&out)
	logger.SetFormatter(&log.JSONFormatter{
		DisableTimestamp:  true,
		DisableHTMLEscape: true,
	})

	consumer := New(Config{
		Logger:   logger,
		MinLevel: "info",
	})
	if err := consumer.InitializeWithRules([]string{ruleDir}); err != nil {
		t.Fatalf("InitializeWithRules() error = %v", err)
	}

	event := &testEvent{
		ts: time.Unix(1700000000, 0).UTC(),
		fields: enrichment.DataFieldsMap{
			"Image":       enrichment.NewStringValue("/usr/bin/whoami"),
			"CommandLine": enrichment.NewStringValue("whoami /all"),
			"ProcessId":   enrichment.NewStringValue("1234"),
		},
	}
	if err := consumer.HandleEvent(event); err != nil {
		t.Fatalf("HandleEvent() error = %v", err)
	}

	var logged map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &logged); err != nil {
		t.Fatalf("failed to decode logged JSON: %v", err)
	}

	if got, _ := logged["rule_author"].(string); got != "Unit Tester" {
		t.Fatalf("rule_author = %q, want Unit Tester", got)
	}
	if got, _ := logged["rule_description"].(string); got == "" {
		t.Fatal("rule_description should be present")
	}
	if got, _ := logged["rule_date"].(string); got != "2026-02-01" {
		t.Fatalf("rule_date = %q, want 2026-02-01", got)
	}
	if got, _ := logged["rule_modified"].(string); got != "2026-02-02" {
		t.Fatalf("rule_modified = %q, want 2026-02-02", got)
	}
	if got, _ := logged["rule_level"].(string); got != "medium" {
		t.Fatalf("rule_level = %q, want medium", got)
	}
	if got, _ := logged["level"].(string); got != "warning" {
		t.Fatalf("level = %q, want warning for medium rule", got)
	}
	if _, exists := logged["sigma_level"]; exists {
		t.Fatalf("sigma_level should not be present, got %#v", logged["sigma_level"])
	}

	gotFields := toStringSetFromAnySlice(logged["sigma_match_fields"])
	if _, ok := gotFields["CommandLine"]; !ok {
		t.Fatalf("sigma_match_fields missing CommandLine: %#v", logged["sigma_match_fields"])
	}
	if _, ok := gotFields["Image"]; !ok {
		t.Fatalf("sigma_match_fields missing Image: %#v", logged["sigma_match_fields"])
	}

	details, ok := logged["sigma_match_details"].(map[string]interface{})
	if !ok {
		t.Fatalf("sigma_match_details has unexpected type: %T", logged["sigma_match_details"])
	}
	cmdDetails := toStringSetFromAnySlice(details["CommandLine"])
	if _, ok := cmdDetails[" /all"]; !ok {
		t.Fatalf("expected CommandLine match detail for ' /all', got %#v", details["CommandLine"])
	}
	imageDetails := toStringSetFromAnySlice(details["Image"])
	if _, ok := imageDetails["/whoami"]; !ok {
		t.Fatalf("expected Image match detail for '/whoami', got %#v", details["Image"])
	}

	matchStrings := toStringSetFromAnySlice(logged["sigma_match_strings"])
	if _, ok := matchStrings["' /all' in CommandLine"]; !ok {
		t.Fatalf("expected sigma_match_strings to include CommandLine reason, got %#v", logged["sigma_match_strings"])
	}
	if _, ok := matchStrings["'/whoami' in Image"]; !ok {
		t.Fatalf("expected sigma_match_strings to include Image reason, got %#v", logged["sigma_match_strings"])
	}
}

func TestSanitizeFieldForLoggingRedactsByKeyName(t *testing.T) {
	got := sanitizeFieldForLogging("dbPassword", "letmein")
	if got != "[REDACTED]" {
		t.Fatalf("expected redaction for sensitive key name, got %q", got)
	}
}

func TestSanitizeFieldForLoggingRedactsCommandLineSecrets(t *testing.T) {
	in := `python app.py --password s3cr3t token=abc123`
	got := sanitizeFieldForLogging("CommandLine", in)
	if strings.Contains(got, "s3cr3t") || strings.Contains(got, "abc123") {
		t.Fatalf("expected command line redaction, got %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction marker in command line, got %q", got)
	}
}

func TestLookupRuleLevelUsesPrecomputedMap(t *testing.T) {
	consumer := New(Config{})
	consumer.ruleLevels["rule-1"] = "critical"

	if got := consumer.lookupRuleLevel("rule-1"); got != "critical" {
		t.Fatalf("lookupRuleLevel() = %q, want critical", got)
	}
	if got := consumer.lookupRuleLevel("missing"); got != "" {
		t.Fatalf("lookupRuleLevel() = %q, want empty string for missing ID", got)
	}
}

func TestSigmaRuleLevelToLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected log.Level
	}{
		{name: "informational", input: "informational", expected: log.InfoLevel},
		{name: "info", input: "info", expected: log.InfoLevel},
		{name: "low", input: "low", expected: log.InfoLevel},
		{name: "medium", input: "medium", expected: log.WarnLevel},
		{name: "high", input: "high", expected: log.ErrorLevel},
		{name: "critical", input: "critical", expected: log.ErrorLevel},
		{name: "unknown", input: "unknown", expected: log.WarnLevel},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := sigmaRuleLevelToLogLevel(tc.input); got != tc.expected {
				t.Fatalf("sigmaRuleLevelToLogLevel(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func BenchmarkLookupRuleLevel(b *testing.B) {
	consumer := New(Config{})
	for i := 0; i < 2000; i++ {
		consumer.ruleLevels["rule-"+strconv.Itoa(i)] = "medium"
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = consumer.lookupRuleLevel("rule-1500")
	}
}

type testEvent struct {
	ts     time.Time
	fields enrichment.DataFieldsMap
}

func (e *testEvent) ID() provider.EventIdentifier { return provider.EventIdentifier{} }
func (e *testEvent) Process() uint32              { return 0 }
func (e *testEvent) Source() string               { return "test" }
func (e *testEvent) Time() time.Time              { return e.ts }
func (e *testEvent) Value(fieldname string) enrichment.DataValue {
	return e.fields.Value(fieldname)
}
func (e *testEvent) ForEach(fn func(key string, value string)) { e.fields.ForEach(fn) }

func writeRuleFile(t *testing.T, dir, fileName, content string) {
	t.Helper()
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func toStringSetFromAnySlice(value interface{}) map[string]struct{} {
	out := make(map[string]struct{})
	slice, ok := value.([]interface{})
	if !ok {
		return out
	}
	for _, item := range slice {
		str, ok := item.(string)
		if !ok {
			continue
		}
		out[str] = struct{}{}
	}
	return out
}
