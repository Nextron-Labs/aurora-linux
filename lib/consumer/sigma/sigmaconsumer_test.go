package sigma

import (
	"bytes"
	"encoding/json"
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
