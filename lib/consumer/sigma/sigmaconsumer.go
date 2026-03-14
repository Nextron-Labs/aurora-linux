package sigma

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sigma "github.com/markuskont/go-sigma-rule-engine"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// SigmaConsumer loads Sigma rules and evaluates events against them.
type SigmaConsumer struct {
	mu sync.RWMutex

	ruleset    *sigma.Ruleset
	ruleLevels map[string]string
	ruleMeta   map[string]ruleMetadata
	minLevel   string
	minPrio    int
	noCollapse bool

	// Throttling: per-rule rate limiter to prevent duplicate spam
	throttles     map[string]*rate.Limiter
	throttleMu    sync.Mutex
	throttleOn    bool
	throttleRate  rate.Limit // matches per second
	throttleBurst int

	// Output
	logger *log.Logger

	// Stats
	matches atomic.Uint64
}

var (
	sensitiveValueFieldNames = []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
	}
	cmdlineInlineSecretPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|api[_-]?key)(\s*[:=]\s*)([^\s"'` + "`" + `]+)`)
	cmdlineFlagSecretPattern   = regexp.MustCompile(`(?i)(--?(?:password|passwd|pwd|token|secret|api[_-]?key))(?:\s+|=)([^\s"'` + "`" + `]+)`)
)

// Config holds configuration for the Sigma consumer.
type Config struct {
	RuleDirs      []string // directories containing Sigma YAML rules
	Logger        *log.Logger
	ThrottleRate  float64 // max matches per rule per second (0 = no throttle)
	ThrottleBurst int     // burst size for throttle
	MinLevel      string  // minimum Sigma level to load (info, low, medium, high, critical)
	NoCollapseWS  bool    // disable sigma whitespace collapsing during pattern matching
}

// New creates a new SigmaConsumer.
func New(cfg Config) *SigmaConsumer {
	throttleOn := cfg.ThrottleRate > 0
	throttleRate := rate.Limit(cfg.ThrottleRate)
	burst := cfg.ThrottleBurst
	if burst <= 0 {
		burst = 5
	}

	minLevel, minPrio, ok := normalizeSigmaLevel(cfg.MinLevel)
	if !ok {
		minLevel = normalizedLevelInfo
		minPrio = levelPriority[minLevel]
	}

	return &SigmaConsumer{
		throttles:     make(map[string]*rate.Limiter),
		ruleLevels:    make(map[string]string),
		ruleMeta:      make(map[string]ruleMetadata),
		minLevel:      minLevel,
		minPrio:       minPrio,
		noCollapse:    cfg.NoCollapseWS,
		throttleOn:    throttleOn,
		throttleRate:  throttleRate,
		throttleBurst: burst,
		logger:        cfg.Logger,
	}
}

func (s *SigmaConsumer) Name() string { return "SigmaConsumer" }

// Initialize loads Sigma rules from the configured rule directories.
func (s *SigmaConsumer) Initialize() error {
	log.Info("SigmaConsumer: initialization placeholder — call InitializeWithRules to load rules")
	return nil
}

// InitializeWithRules loads rules from the given rule directories.
func (s *SigmaConsumer) InitializeWithRules(ruleDirs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory:       ruleDirs,
		FailOnRuleParse: false,
		FailOnYamlParse: false,
		NoCollapseWS:    s.noCollapse,
	})
	if err != nil {
		return fmt.Errorf("creating sigma ruleset: %w", err)
	}

	filteredRules := make([]*sigma.Tree, 0, len(ruleset.Rules))
	s.ruleLevels = make(map[string]string, len(ruleset.Rules))
	s.ruleMeta = make(map[string]ruleMetadata, len(ruleset.Rules))
	for _, tree := range ruleset.Rules {
		if tree == nil || tree.Rule == nil {
			continue
		}
		if !passesMinLevel(tree.Rule.Level, s.minPrio) {
			continue
		}

		filteredRules = append(filteredRules, tree)

		lookupKey := ruleLookupKey(tree.Rule.ID, tree.Rule.Title)
		s.ruleLevels[lookupKey] = tree.Rule.Level
		s.ruleMeta[lookupKey] = buildRuleMetadata(tree)
	}
	ruleset.Rules = filteredRules
	s.ruleset = ruleset

	if len(ruleDirs) > 0 && len(ruleset.Rules) == 0 {
		return fmt.Errorf(
			"no loadable Sigma rules found in %v for --min-level=%q (total=%d failed=%d unsupported=%d)",
			ruleDirs, s.minLevel, ruleset.Total, ruleset.Failed, ruleset.Unsupported,
		)
	}

	log.WithFields(log.Fields{
		"total":        ruleset.Total,
		"ok":           ruleset.Ok,
		"loaded":       len(ruleset.Rules),
		"min_level":    s.minLevel,
		"failed":       ruleset.Failed,
		"unsupported":  ruleset.Unsupported,
		"filtered_out": ruleset.Ok - len(ruleset.Rules),
	}).Info("Sigma rules loaded")

	return nil
}

// HandleEvent evaluates the event against all loaded Sigma rules.
func (s *SigmaConsumer) HandleEvent(event provider.Event) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ruleset == nil {
		return nil
	}

	wrapped := &sigmaEventWrapper{event: event}

	results, match := s.ruleset.EvalAll(wrapped)
	if !match {
		return nil
	}

	for _, result := range results {
		ruleID := result.ID
		if ruleID == "" {
			ruleID = result.Title
		}

		// Throttle check
		if !s.allowMatch(ruleID) {
			continue
		}

		s.matches.Add(1)
		s.emitMatch(event, result)
	}

	return nil
}

// allowMatch checks the per-rule rate limiter. Returns true if this match
// should be emitted.
func (s *SigmaConsumer) allowMatch(ruleID string) bool {
	if !s.throttleOn {
		return true
	}

	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()

	limiter, ok := s.throttles[ruleID]
	if !ok {
		limiter = rate.NewLimiter(s.throttleRate, s.throttleBurst)
		s.throttles[ruleID] = limiter
	}

	return limiter.Allow()
}

// emitMatch logs a Sigma match.
func (s *SigmaConsumer) emitMatch(event provider.Event, result sigma.Result) {
	lookupKey := ruleLookupKey(result.ID, result.Title)
	ruleLevel := s.lookupRuleLevel(lookupKey)

	fields := log.Fields{
		"sigma_rule":  result.ID,
		"sigma_title": result.Title,
		"timestamp":   event.Time().Format(time.RFC3339Nano),
	}

	if len(result.Tags) > 0 {
		fields["sigma_tags"] = result.Tags
	}
	s.addRuleMetadataFields(fields, lookupKey)
	s.addMatchEvidenceFields(fields, lookupKey, event)

	// Add all event data fields
	event.ForEach(func(key, value string) {
		value = sanitizeFieldForLogging(key, value)

		if _, exists := fields[key]; exists {
			key = "event_" + key
			if _, exists := fields[key]; exists {
				return
			}
		}
		fields[key] = value
	})

	logLevel := sigmaRuleLevelToLogLevel(ruleLevel)
	if s.logger != nil {
		entry := log.Entry{Logger: s.logger, Data: fields}
		entry.Log(logLevel, "Sigma match")
	} else {
		entry := log.Entry{Logger: log.StandardLogger(), Data: fields}
		entry.Log(logLevel, "Sigma match")
	}
}

func sanitizeFieldForLogging(key, value string) string {
	keyLower := strings.ToLower(key)
	for _, marker := range sensitiveValueFieldNames {
		if strings.Contains(keyLower, marker) {
			return "[REDACTED]"
		}
	}

	switch key {
	case "CommandLine", "ParentCommandLine":
		value = cmdlineInlineSecretPattern.ReplaceAllString(value, `$1$2[REDACTED]`)
		value = cmdlineFlagSecretPattern.ReplaceAllString(value, `$1 [REDACTED]`)
	}

	return value
}

// lookupRuleLevel finds the level string for a rule by its ID.
func (s *SigmaConsumer) lookupRuleLevel(ruleID string) string {
	if s.ruleLevels == nil {
		return ""
	}
	return s.ruleLevels[ruleID]
}

func sigmaRuleLevelToLogLevel(ruleLevel string) log.Level {
	normalizedLevel, _, ok := normalizeSigmaLevel(ruleLevel)
	if !ok {
		return log.WarnLevel
	}

	switch normalizedLevel {
	case normalizedLevelInfo, normalizedLevelLow:
		return log.InfoLevel
	case normalizedLevelMedium:
		return log.WarnLevel
	case normalizedLevelHigh, normalizedLevelCritical:
		return log.ErrorLevel
	default:
		return log.WarnLevel
	}
}

// Matches returns the number of Sigma matches detected.
func (s *SigmaConsumer) Matches() uint64 {
	return s.matches.Load()
}

// Close cleans up the consumer.
func (s *SigmaConsumer) Close() error {
	return nil
}

// sigmaEventWrapper adapts a provider.Event to the go-sigma-rule-engine Event
// interface (Keyworder + Selector).
type sigmaEventWrapper struct {
	event provider.Event
}

// Select implements sigma.Selector — performs key-value lookup for structured data.
func (w *sigmaEventWrapper) Select(key string) (interface{}, bool) {
	v := w.event.Value(key)
	if !v.Valid {
		return nil, false
	}
	return v.String, true
}

// Keywords implements sigma.Keyworder — returns unstructured message fields.
func (w *sigmaEventWrapper) Keywords() ([]string, bool) {
	var keywords []string
	w.event.ForEach(func(key, value string) {
		keywords = append(keywords, value)
	})
	if len(keywords) == 0 {
		return nil, false
	}
	return keywords, true
}

// sigmaEventWrapperForReplay adapts a DataFieldsMap to go-sigma-rule-engine Event.
type sigmaEventWrapperForReplay struct {
	fields map[string]string
}

// Select implements sigma.Selector.
func (w *sigmaEventWrapperForReplay) Select(key string) (interface{}, bool) {
	v, ok := w.fields[key]
	return v, ok
}

// Keywords implements sigma.Keyworder.
func (w *sigmaEventWrapperForReplay) Keywords() ([]string, bool) {
	var keywords []string
	for _, v := range w.fields {
		keywords = append(keywords, v)
	}
	if len(keywords) == 0 {
		return nil, false
	}
	return keywords, true
}

// EvalFieldsMap evaluates a map of field values against all rules. Used by
// the replay provider for testing.
func (s *SigmaConsumer) EvalFieldsMap(fields map[string]string) []sigma.Result {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ruleset == nil {
		return nil
	}

	wrapped := &sigmaEventWrapperForReplay{fields: fields}
	results, match := s.ruleset.EvalAll(wrapped)
	if !match {
		return nil
	}
	return results
}

// FormatMatchMessage creates a human-readable match description.
func FormatMatchMessage(event provider.Event, result sigma.Result, level string) string {
	image := event.Value("Image").String
	cmdline := event.Value("CommandLine").String
	pid := event.Value("ProcessId").String

	return fmt.Sprintf(
		"[%s] %s | PID=%s Image=%s CommandLine=%s",
		level, result.ID, pid, image, cmdline,
	)
}
