package sigma

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

// CorrelationType represents the type of a Sigma correlation rule.
type CorrelationType string

const (
	CorrelationEventCount      CorrelationType = "event_count"
	CorrelationValueCount      CorrelationType = "value_count"
	CorrelationTemporal        CorrelationType = "temporal"
	CorrelationOrderedTemporal CorrelationType = "ordered_temporal"
)

// CorrelationRule represents a parsed Sigma correlation rule.
type CorrelationRule struct {
	ID             string
	Title          string
	Name           string
	Level          string
	Status         string
	Author         string
	Description    string
	Date           string
	Modified       string
	Tags           []string
	FalsePositives []string
	References     []string
	Path           string

	Type      CorrelationType
	Rules     []string                     // referenced rule IDs/names
	GroupBy   []string                     // fields to group events by
	Timespan  time.Duration                // time window
	Condition correlationCondition
	Aliases   map[string]map[string]string // virtual_field -> rule_id -> actual_field
	Generate  bool
}

type correlationCondition struct {
	Field string // for value_count: which field to count distinct values of
	GTE   int
	LTE   int
	GT    int
	LT    int
	EQ    int
}

// correlationRuleYAML is the YAML representation for unmarshaling.
type correlationRuleYAML struct {
	Title          string   `yaml:"title"`
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	Status         string   `yaml:"status"`
	Description    string   `yaml:"description"`
	Author         string   `yaml:"author"`
	Date           string   `yaml:"date"`
	Modified       string   `yaml:"modified"`
	Level          string   `yaml:"level"`
	Tags           []string `yaml:"tags"`
	FalsePositives []string `yaml:"falsepositives"`
	References     []string `yaml:"references"`
	Correlation    struct {
		Type      string                       `yaml:"type"`
		Rules     []string                     `yaml:"rules"`
		GroupBy   []string                     `yaml:"group-by"`
		Timespan  string                       `yaml:"timespan"`
		Condition map[string]interface{}        `yaml:"condition"`
		Aliases   map[string]map[string]string `yaml:"aliases"`
		Generate  bool                         `yaml:"generate"`
	} `yaml:"correlation"`
}

// parseCorrelationRule reads a YAML file and returns a CorrelationRule.
func parseCorrelationRule(path string) (*CorrelationRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw correlationRuleYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	corrType := CorrelationType(raw.Correlation.Type)
	switch corrType {
	case CorrelationEventCount, CorrelationValueCount,
		CorrelationTemporal, CorrelationOrderedTemporal:
	default:
		return nil, fmt.Errorf("unknown correlation type %q in %s", raw.Correlation.Type, path)
	}

	timespan, err := parseSigmaDuration(raw.Correlation.Timespan)
	if err != nil {
		return nil, fmt.Errorf("parsing timespan in %s: %w", path, err)
	}

	cond, err := parseCondition(raw.Correlation.Condition, corrType)
	if err != nil {
		return nil, fmt.Errorf("parsing condition in %s: %w", path, err)
	}

	return &CorrelationRule{
		ID:             raw.ID,
		Title:          raw.Title,
		Name:           raw.Name,
		Level:          raw.Level,
		Status:         raw.Status,
		Author:         raw.Author,
		Description:    raw.Description,
		Date:           raw.Date,
		Modified:       raw.Modified,
		Tags:           raw.Tags,
		FalsePositives: raw.FalsePositives,
		References:     raw.References,
		Path:           path,
		Type:           corrType,
		Rules:          raw.Correlation.Rules,
		GroupBy:        raw.Correlation.GroupBy,
		Timespan:       timespan,
		Condition:      cond,
		Aliases:        raw.Correlation.Aliases,
		Generate:       raw.Correlation.Generate,
	}, nil
}

// parseSigmaDuration parses Sigma duration strings like "5m", "1h", "30s", "1d".
func parseSigmaDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty timespan")
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("invalid timespan %q", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("timespan must be positive, got %q", s)
	}

	switch unit {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown timespan unit %q in %q", string(unit), s)
	}
}

func parseCondition(raw map[string]interface{}, corrType CorrelationType) (correlationCondition, error) {
	var cond correlationCondition

	// temporal and ordered_temporal fire when all rules match; no threshold needed.
	if corrType == CorrelationTemporal || corrType == CorrelationOrderedTemporal {
		return cond, nil
	}

	if len(raw) == 0 {
		return cond, fmt.Errorf("condition is required for %s", corrType)
	}

	if field, ok := raw["field"]; ok {
		if s, ok := field.(string); ok {
			cond.Field = s
		}
	}

	if v, ok := raw["gte"]; ok {
		cond.GTE = toInt(v)
	}
	if v, ok := raw["lte"]; ok {
		cond.LTE = toInt(v)
	}
	if v, ok := raw["gt"]; ok {
		cond.GT = toInt(v)
	}
	if v, ok := raw["lt"]; ok {
		cond.LT = toInt(v)
	}
	if v, ok := raw["eq"]; ok {
		cond.EQ = toInt(v)
	}

	if corrType == CorrelationValueCount && cond.Field == "" {
		return cond, fmt.Errorf("value_count requires a 'field' in condition")
	}

	return cond, nil
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Correlation engine
// ---------------------------------------------------------------------------

// matchRecord is a timestamped record of a base rule match.
type matchRecord struct {
	timestamp time.Time
	ruleID    string
	fields    map[string]string
}

type windowKey struct {
	ruleID   string // correlation rule ID
	groupKey string // concatenated group-by values
}

// CorrelationEngine tracks base rule matches and evaluates correlation rules.
type CorrelationEngine struct {
	rules      []*CorrelationRule
	rulesByRef map[string][]*CorrelationRule // base rule ID -> correlation rules

	mu         sync.Mutex
	windows    map[windowKey][]matchRecord
	suppressed map[windowKey]time.Time
}

// NewCorrelationEngine creates a new engine with the given correlation rules.
func NewCorrelationEngine(rules []*CorrelationRule) *CorrelationEngine {
	rulesByRef := make(map[string][]*CorrelationRule)
	for _, r := range rules {
		for _, ref := range r.Rules {
			rulesByRef[ref] = append(rulesByRef[ref], r)
		}
	}

	log.WithFields(log.Fields{
		"correlation_rules": len(rules),
		"base_rules_tracked": len(rulesByRef),
	}).Info("Correlation engine initialized")

	return &CorrelationEngine{
		rules:      rules,
		rulesByRef: rulesByRef,
		windows:    make(map[windowKey][]matchRecord),
		suppressed: make(map[windowKey]time.Time),
	}
}

// CorrelationMatch represents a triggered correlation rule.
type CorrelationMatch struct {
	Rule  *CorrelationRule
	Count int
	Group string
}

// TrackMatch records a base rule match and returns any triggered correlation alerts.
func (e *CorrelationEngine) TrackMatch(baseRuleID string, ts time.Time, fields map[string]string) []CorrelationMatch {
	corrRules := e.rulesByRef[baseRuleID]
	if len(corrRules) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var matches []CorrelationMatch
	for _, cr := range corrRules {
		groupKey := e.buildGroupKey(cr, baseRuleID, fields)
		wk := windowKey{ruleID: cr.ID, groupKey: groupKey}

		// Check suppression: after firing, suppress for the timespan duration.
		if suppUntil, ok := e.suppressed[wk]; ok {
			if ts.Before(suppUntil) {
				continue
			}
			delete(e.suppressed, wk)
		}

		// Add entry.
		e.windows[wk] = append(e.windows[wk], matchRecord{
			timestamp: ts,
			ruleID:    baseRuleID,
			fields:    fields,
		})

		// Prune entries outside the time window.
		cutoff := ts.Add(-cr.Timespan)
		entries := e.windows[wk]
		start := 0
		for start < len(entries) && entries[start].timestamp.Before(cutoff) {
			start++
		}
		if start > 0 {
			e.windows[wk] = entries[start:]
		}

		// Evaluate.
		if cm, ok := e.evaluate(cr, wk); ok {
			matches = append(matches, cm)
			e.suppressed[wk] = ts.Add(cr.Timespan)
			delete(e.windows, wk)
		}
	}

	return matches
}

func (e *CorrelationEngine) buildGroupKey(cr *CorrelationRule, baseRuleID string, fields map[string]string) string {
	if len(cr.GroupBy) == 0 {
		return ""
	}

	parts := make([]string, len(cr.GroupBy))
	for i, groupField := range cr.GroupBy {
		actualField := groupField
		if cr.Aliases != nil {
			if aliasMap, ok := cr.Aliases[groupField]; ok {
				if mapped, ok := aliasMap[baseRuleID]; ok {
					actualField = mapped
				}
			}
		}
		parts[i] = fields[actualField]
	}
	return strings.Join(parts, "\x00")
}

func (e *CorrelationEngine) evaluate(cr *CorrelationRule, wk windowKey) (CorrelationMatch, bool) {
	entries := e.windows[wk]

	switch cr.Type {
	case CorrelationEventCount:
		count := len(entries)
		if matchesThreshold(count, cr.Condition) {
			return CorrelationMatch{Rule: cr, Count: count, Group: wk.groupKey}, true
		}

	case CorrelationValueCount:
		distinct := make(map[string]struct{})
		for _, entry := range entries {
			if v, ok := entry.fields[cr.Condition.Field]; ok && v != "" {
				distinct[v] = struct{}{}
			}
		}
		count := len(distinct)
		if matchesThreshold(count, cr.Condition) {
			return CorrelationMatch{Rule: cr, Count: count, Group: wk.groupKey}, true
		}

	case CorrelationTemporal:
		seen := make(map[string]struct{}, len(cr.Rules))
		for _, entry := range entries {
			seen[entry.ruleID] = struct{}{}
		}
		if len(seen) >= len(cr.Rules) {
			allSeen := true
			for _, ref := range cr.Rules {
				if _, ok := seen[ref]; !ok {
					allSeen = false
					break
				}
			}
			if allSeen {
				return CorrelationMatch{Rule: cr, Count: len(entries), Group: wk.groupKey}, true
			}
		}

	case CorrelationOrderedTemporal:
		idx := 0
		for _, entry := range entries {
			if idx < len(cr.Rules) && entry.ruleID == cr.Rules[idx] {
				idx++
			}
		}
		if idx >= len(cr.Rules) {
			return CorrelationMatch{Rule: cr, Count: len(entries), Group: wk.groupKey}, true
		}
	}

	return CorrelationMatch{}, false
}

func matchesThreshold(count int, cond correlationCondition) bool {
	if cond.GTE > 0 && count < cond.GTE {
		return false
	}
	if cond.GT > 0 && count <= cond.GT {
		return false
	}
	if cond.LTE > 0 && count > cond.LTE {
		return false
	}
	if cond.LT > 0 && count >= cond.LT {
		return false
	}
	if cond.EQ > 0 && count != cond.EQ {
		return false
	}
	return true
}
