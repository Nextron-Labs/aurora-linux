package sigma

import (
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Duration parsing
// ---------------------------------------------------------------------------

func TestParseSigmaDuration(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"5m", 5 * time.Minute, false},
		{"30s", 30 * time.Second, false},
		{"1h", 1 * time.Hour, false},
		{"2d", 48 * time.Hour, false},
		{"", 0, true},
		{"5x", 0, true},
		{"-1m", 0, true},
	}
	for _, tc := range tests {
		got, err := parseSigmaDuration(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseSigmaDuration(%q) expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSigmaDuration(%q) error = %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSigmaDuration(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// YAML parsing
// ---------------------------------------------------------------------------

func TestParseCorrelationRule(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "event_count.yml", `title: PAM Bruteforce
id: bbbb2222-2222-2222-2222-222222222222
name: pam_bruteforce
status: test
author: Unit Test
description: Bruteforce detection
level: high
tags:
  - attack.t1110
correlation:
  type: event_count
  rules:
    - aaaa1111-1111-1111-1111-111111111111
  group-by:
    - TargetUser
  timespan: 5m
  condition:
    gte: 5
`)

	cr, err := parseCorrelationRule(filepath.Join(dir, "event_count.yml"))
	if err != nil {
		t.Fatalf("parseCorrelationRule() error = %v", err)
	}
	if cr.Type != CorrelationEventCount {
		t.Errorf("Type = %q, want event_count", cr.Type)
	}
	if cr.Timespan != 5*time.Minute {
		t.Errorf("Timespan = %v, want 5m", cr.Timespan)
	}
	if cr.Condition.GTE != 5 {
		t.Errorf("Condition.GTE = %d, want 5", cr.Condition.GTE)
	}
	if len(cr.GroupBy) != 1 || cr.GroupBy[0] != "TargetUser" {
		t.Errorf("GroupBy = %v, want [TargetUser]", cr.GroupBy)
	}
	if len(cr.Rules) != 1 {
		t.Errorf("Rules = %v, want 1 entry", cr.Rules)
	}
}

func TestParseCorrelationRuleValueCount(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "value_count.yml", `title: Login Spray
id: cccc3333-3333-3333-3333-333333333333
level: high
correlation:
  type: value_count
  rules:
    - aaaa1111-1111-1111-1111-111111111111
  group-by:
    - TargetUser
  timespan: 15m
  condition:
    field: SourceIP
    gte: 5
`)

	cr, err := parseCorrelationRule(filepath.Join(dir, "value_count.yml"))
	if err != nil {
		t.Fatalf("parseCorrelationRule() error = %v", err)
	}
	if cr.Type != CorrelationValueCount {
		t.Errorf("Type = %q, want value_count", cr.Type)
	}
	if cr.Condition.Field != "SourceIP" {
		t.Errorf("Condition.Field = %q, want SourceIP", cr.Condition.Field)
	}
}

func TestParseCorrelationRuleRejectsValueCountWithoutField(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "bad.yml", `title: Bad
id: dddd4444-4444-4444-4444-444444444444
level: high
correlation:
  type: value_count
  rules:
    - aaaa1111-1111-1111-1111-111111111111
  timespan: 5m
  condition:
    gte: 5
`)

	_, err := parseCorrelationRule(filepath.Join(dir, "bad.yml"))
	if err == nil {
		t.Fatal("expected error for value_count without field")
	}
}

// ---------------------------------------------------------------------------
// Engine: event_count
// ---------------------------------------------------------------------------

func TestCorrelationEventCount(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-1",
		Title:    "Bruteforce",
		Level:    "high",
		Type:     CorrelationEventCount,
		Rules:    []string{"base-rule"},
		Timespan: 5 * time.Minute,
		Condition: correlationCondition{GTE: 3},
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	fields := map[string]string{"user": "root"}

	// First two matches: no alert.
	for i := 0; i < 2; i++ {
		matches := engine.TrackMatch("base-rule", now.Add(time.Duration(i)*time.Second), fields)
		if len(matches) != 0 {
			t.Fatalf("match %d: got %d correlation matches, want 0", i+1, len(matches))
		}
	}

	// Third match: threshold reached.
	matches := engine.TrackMatch("base-rule", now.Add(2*time.Second), fields)
	if len(matches) != 1 {
		t.Fatalf("match 3: got %d correlation matches, want 1", len(matches))
	}
	if matches[0].Count != 3 {
		t.Errorf("Count = %d, want 3", matches[0].Count)
	}
}

func TestCorrelationEventCountSuppression(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-1",
		Type:     CorrelationEventCount,
		Rules:    []string{"base-rule"},
		Timespan: 5 * time.Minute,
		Condition: correlationCondition{GTE: 2},
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	fields := map[string]string{}

	// Fire it.
	engine.TrackMatch("base-rule", now, fields)
	matches := engine.TrackMatch("base-rule", now.Add(time.Second), fields)
	if len(matches) != 1 {
		t.Fatalf("expected initial fire, got %d matches", len(matches))
	}

	// Within suppression window: should not fire again even with enough events.
	engine.TrackMatch("base-rule", now.Add(2*time.Second), fields)
	matches = engine.TrackMatch("base-rule", now.Add(3*time.Second), fields)
	if len(matches) != 0 {
		t.Fatal("expected suppression, got a match")
	}

	// After suppression window expires: should fire again.
	engine.TrackMatch("base-rule", now.Add(6*time.Minute), fields)
	matches = engine.TrackMatch("base-rule", now.Add(6*time.Minute+time.Second), fields)
	if len(matches) != 1 {
		t.Fatal("expected fire after suppression expired")
	}
}

func TestCorrelationEventCountExpiry(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-1",
		Type:     CorrelationEventCount,
		Rules:    []string{"base-rule"},
		Timespan: 1 * time.Minute,
		Condition: correlationCondition{GTE: 3},
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	fields := map[string]string{}

	// Two events now.
	engine.TrackMatch("base-rule", now, fields)
	engine.TrackMatch("base-rule", now.Add(time.Second), fields)

	// Third event 2 minutes later — first two have expired.
	matches := engine.TrackMatch("base-rule", now.Add(2*time.Minute), fields)
	if len(matches) != 0 {
		t.Fatal("old events should have expired, should not fire")
	}
}

func TestCorrelationEventCountGroupBy(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-1",
		Type:     CorrelationEventCount,
		Rules:    []string{"base-rule"},
		GroupBy:  []string{"user"},
		Timespan: 5 * time.Minute,
		Condition: correlationCondition{GTE: 2},
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()

	// One event for user=alice, one for user=bob — neither group hits threshold.
	engine.TrackMatch("base-rule", now, map[string]string{"user": "alice"})
	matches := engine.TrackMatch("base-rule", now.Add(time.Second), map[string]string{"user": "bob"})
	if len(matches) != 0 {
		t.Fatal("different groups should not combine")
	}

	// Second event for alice — now alice's group fires.
	matches = engine.TrackMatch("base-rule", now.Add(2*time.Second), map[string]string{"user": "alice"})
	if len(matches) != 1 {
		t.Fatalf("expected alice group to fire, got %d matches", len(matches))
	}
}

// ---------------------------------------------------------------------------
// Engine: value_count
// ---------------------------------------------------------------------------

func TestCorrelationValueCount(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-vc",
		Type:     CorrelationValueCount,
		Rules:    []string{"base-rule"},
		GroupBy:  []string{"user"},
		Timespan: 5 * time.Minute,
		Condition: correlationCondition{Field: "SourceIP", GTE: 3},
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	user := map[string]string{"user": "alice"}

	// Two distinct IPs — not enough.
	engine.TrackMatch("base-rule", now, merge(user, "SourceIP", "10.0.0.1"))
	engine.TrackMatch("base-rule", now.Add(time.Second), merge(user, "SourceIP", "10.0.0.2"))
	// Duplicate IP — still 2 distinct.
	matches := engine.TrackMatch("base-rule", now.Add(2*time.Second), merge(user, "SourceIP", "10.0.0.1"))
	if len(matches) != 0 {
		t.Fatal("2 distinct IPs should not fire with gte=3")
	}

	// Third distinct IP — fires.
	matches = engine.TrackMatch("base-rule", now.Add(3*time.Second), merge(user, "SourceIP", "10.0.0.3"))
	if len(matches) != 1 {
		t.Fatalf("3 distinct IPs should fire, got %d matches", len(matches))
	}
	if matches[0].Count != 3 {
		t.Errorf("Count = %d, want 3 (distinct values)", matches[0].Count)
	}
}

// ---------------------------------------------------------------------------
// Engine: temporal
// ---------------------------------------------------------------------------

func TestCorrelationTemporal(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-temp",
		Type:     CorrelationTemporal,
		Rules:    []string{"rule-A", "rule-B"},
		Timespan: 5 * time.Minute,
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	fields := map[string]string{}

	// Only rule-A fires — not enough.
	matches := engine.TrackMatch("rule-A", now, fields)
	if len(matches) != 0 {
		t.Fatal("single rule should not fire temporal")
	}

	// rule-B fires within window — both rules seen.
	matches = engine.TrackMatch("rule-B", now.Add(time.Minute), fields)
	if len(matches) != 1 {
		t.Fatal("both rules within window should fire temporal")
	}
}

func TestCorrelationTemporalExpiry(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-temp",
		Type:     CorrelationTemporal,
		Rules:    []string{"rule-A", "rule-B"},
		Timespan: 1 * time.Minute,
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	fields := map[string]string{}

	// rule-A fires.
	engine.TrackMatch("rule-A", now, fields)

	// rule-B fires AFTER the window — rule-A has expired.
	matches := engine.TrackMatch("rule-B", now.Add(2*time.Minute), fields)
	if len(matches) != 0 {
		t.Fatal("rule-A expired, should not fire temporal")
	}
}

// ---------------------------------------------------------------------------
// Engine: ordered_temporal
// ---------------------------------------------------------------------------

func TestCorrelationOrderedTemporal(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-ord",
		Type:     CorrelationOrderedTemporal,
		Rules:    []string{"rule-A", "rule-B"},
		Timespan: 5 * time.Minute,
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	fields := map[string]string{}

	// Wrong order: B then A — should not fire.
	engine.TrackMatch("rule-B", now, fields)
	matches := engine.TrackMatch("rule-A", now.Add(time.Second), fields)
	if len(matches) != 0 {
		t.Fatal("wrong order should not fire ordered_temporal")
	}
}

func TestCorrelationOrderedTemporalCorrectOrder(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-ord",
		Type:     CorrelationOrderedTemporal,
		Rules:    []string{"rule-A", "rule-B"},
		Timespan: 5 * time.Minute,
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()
	fields := map[string]string{}

	// Correct order: A then B.
	engine.TrackMatch("rule-A", now, fields)
	matches := engine.TrackMatch("rule-B", now.Add(time.Second), fields)
	if len(matches) != 1 {
		t.Fatal("correct order should fire ordered_temporal")
	}
}

// ---------------------------------------------------------------------------
// Engine: aliases
// ---------------------------------------------------------------------------

func TestCorrelationAliases(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-alias",
		Type:     CorrelationTemporal,
		Rules:    []string{"rule-A", "rule-B"},
		GroupBy:  []string{"src"},
		Timespan: 5 * time.Minute,
		Aliases: map[string]map[string]string{
			"src": {
				"rule-A": "SourceIP",
				"rule-B": "ClientAddr",
			},
		},
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	now := time.Now()

	// rule-A uses SourceIP, rule-B uses ClientAddr — same value groups them.
	engine.TrackMatch("rule-A", now, map[string]string{"SourceIP": "10.0.0.1"})
	matches := engine.TrackMatch("rule-B", now.Add(time.Second), map[string]string{"ClientAddr": "10.0.0.1"})
	if len(matches) != 1 {
		t.Fatal("aliased fields with same value should group together")
	}

	// Different values should NOT group.
	engine2 := NewCorrelationEngine([]*CorrelationRule{cr})
	engine2.TrackMatch("rule-A", now, map[string]string{"SourceIP": "10.0.0.1"})
	matches = engine2.TrackMatch("rule-B", now.Add(time.Second), map[string]string{"ClientAddr": "10.0.0.2"})
	if len(matches) != 0 {
		t.Fatal("aliased fields with different values should not group together")
	}
}

// ---------------------------------------------------------------------------
// Engine: unrelated base rule
// ---------------------------------------------------------------------------

func TestCorrelationIgnoresUnrelatedRules(t *testing.T) {
	cr := &CorrelationRule{
		ID:       "corr-1",
		Type:     CorrelationEventCount,
		Rules:    []string{"base-rule"},
		Timespan: 5 * time.Minute,
		Condition: correlationCondition{GTE: 1},
	}
	engine := NewCorrelationEngine([]*CorrelationRule{cr})

	matches := engine.TrackMatch("other-rule", time.Now(), map[string]string{})
	if len(matches) != 0 {
		t.Fatal("unrelated rule should not trigger correlation")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func merge(base map[string]string, key, value string) map[string]string {
	m := make(map[string]string, len(base)+1)
	for k, v := range base {
		m[k] = v
	}
	m[key] = value
	return m
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	writeRuleFile(t, dir, name, content)
}
