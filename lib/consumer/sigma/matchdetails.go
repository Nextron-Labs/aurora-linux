package sigma

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	sigmaengine "github.com/markuskont/go-sigma-rule-engine"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

type ruleMetadata struct {
	ID             string
	Title          string
	Level          string
	Author         string
	Description    string
	Status         string
	Date           string
	Modified       string
	Path           string
	References     []string
	Tags           []string
	FalsePositives []string
	NoCollapseWS   bool

	Tree          *sigmaengine.Tree
	FieldPatterns map[string][]ruleFieldPattern
}

type ruleFieldPattern struct {
	Modifiers []string
	Pattern   string
	Matcher   sigmaengine.StringMatcher
}

type fieldPatternMatch struct {
	Field   string
	Pattern string
}

func ruleLookupKey(id, title string) string {
	id = strings.TrimSpace(id)
	if id != "" {
		return id
	}
	return strings.TrimSpace(title)
}

func buildRuleMetadata(tree *sigmaengine.Tree) ruleMetadata {
	meta := ruleMetadata{
		Tree: tree,
	}
	if tree == nil || tree.Rule == nil {
		return meta
	}

	rule := tree.Rule
	meta.ID = strings.TrimSpace(rule.ID)
	meta.Title = strings.TrimSpace(rule.Title)
	meta.Level = strings.TrimSpace(strings.ToLower(rule.Level))
	meta.Author = strings.TrimSpace(rule.Author)
	meta.Description = strings.TrimSpace(rule.Description)
	meta.Status = strings.TrimSpace(rule.Status)
	meta.Path = strings.TrimSpace(rule.Path)
	meta.References = append([]string(nil), rule.References...)
	meta.Tags = append([]string(nil), rule.Tags...)
	meta.FalsePositives = append([]string(nil), rule.Falsepositives...)
	meta.NoCollapseWS = rule.NoCollapseWS
	meta.FieldPatterns = extractDetectionFieldPatterns(rule.Detection, meta.NoCollapseWS)
	meta.Date, meta.Modified = readRuleDateMetadata(rule.Path)
	return meta
}

func (s *SigmaConsumer) addRuleMetadataFields(fields log.Fields, lookupKey string) {
	meta, ok := s.ruleMeta[lookupKey]
	if !ok {
		return
	}

	if meta.ID != "" {
		fields["rule_id"] = meta.ID
	}
	if meta.Title != "" {
		fields["rule_title"] = meta.Title
	}
	if meta.Level != "" {
		fields["rule_level"] = meta.Level
	}
	if meta.Author != "" {
		fields["rule_author"] = meta.Author
	}
	if meta.Description != "" {
		fields["rule_description"] = meta.Description
	}
	if meta.Status != "" {
		fields["rule_status"] = meta.Status
	}
	if meta.Date != "" {
		fields["rule_date"] = meta.Date
	}
	if meta.Modified != "" {
		fields["rule_modified"] = meta.Modified
	}
	if meta.Path != "" {
		fields["rule_path"] = meta.Path
	}
	if len(meta.References) > 0 {
		fields["rule_references"] = meta.References
	}
	if len(meta.Tags) > 0 {
		fields["rule_tags"] = meta.Tags
	}
	if len(meta.FalsePositives) > 0 {
		fields["rule_falsepositives"] = meta.FalsePositives
	}
}

func (s *SigmaConsumer) addMatchEvidenceFields(fields log.Fields, lookupKey string, event provider.Event) {
	meta, ok := s.ruleMeta[lookupKey]
	if !ok || meta.Tree == nil || meta.Tree.Root == nil {
		return
	}

	matches := collectRuleMatchEvidence(meta, event)
	if len(matches) == 0 {
		return
	}

	matchFields, matchDetails, matchStrings := formatMatchEvidence(matches)
	if len(matchFields) > 0 {
		fields["sigma_match_fields"] = matchFields
	}
	if len(matchDetails) > 0 {
		fields["sigma_match_details"] = matchDetails
	}
	if len(matchStrings) > 0 {
		fields["sigma_match_strings"] = matchStrings
	}
}

func collectRuleMatchEvidence(meta ruleMetadata, event provider.Event) []fieldPatternMatch {
	wrapped := &sigmaEventWrapper{event: event}
	match, applicable, matches := evalBranchForEvidence(meta.Tree.Root, wrapped, false, meta)
	if !match || !applicable {
		return nil
	}
	return matches
}

func evalBranchForEvidence(
	branch sigmaengine.Branch,
	event sigmaengine.Event,
	negated bool,
	meta ruleMetadata,
) (bool, bool, []fieldPatternMatch) {
	switch b := branch.(type) {
	case sigmaengine.NodeSimpleAnd:
		allMatches := make([]fieldPatternMatch, 0)
		for _, child := range b {
			match, applicable, childMatches := evalBranchForEvidence(child, event, negated, meta)
			if !match || !applicable {
				return match, applicable, nil
			}
			allMatches = append(allMatches, childMatches...)
		}
		return true, true, allMatches
	case sigmaengine.NodeSimpleOr:
		oneApplicable := false
		anyMatch := false
		allMatches := make([]fieldPatternMatch, 0)
		for _, child := range b {
			match, applicable, childMatches := evalBranchForEvidence(child, event, negated, meta)
			if applicable {
				oneApplicable = true
			}
			if match {
				anyMatch = true
				allMatches = append(allMatches, childMatches...)
			}
		}
		if anyMatch {
			return true, true, allMatches
		}
		return false, oneApplicable, nil
	case *sigmaengine.NodeAnd:
		leftMatch, leftApplicable, leftMatches := evalBranchForEvidence(b.L, event, negated, meta)
		if !leftMatch {
			return false, leftApplicable, nil
		}
		rightMatch, rightApplicable, rightMatches := evalBranchForEvidence(b.R, event, negated, meta)
		if !rightMatch || !rightApplicable {
			return rightMatch, rightApplicable, nil
		}
		return true, leftApplicable && rightApplicable, append(leftMatches, rightMatches...)
	case sigmaengine.NodeAnd:
		leftMatch, leftApplicable, leftMatches := evalBranchForEvidence(b.L, event, negated, meta)
		if !leftMatch {
			return false, leftApplicable, nil
		}
		rightMatch, rightApplicable, rightMatches := evalBranchForEvidence(b.R, event, negated, meta)
		if !rightMatch || !rightApplicable {
			return rightMatch, rightApplicable, nil
		}
		return true, leftApplicable && rightApplicable, append(leftMatches, rightMatches...)
	case *sigmaengine.NodeOr:
		leftMatch, leftApplicable, leftMatches := evalBranchForEvidence(b.L, event, negated, meta)
		if leftMatch {
			return true, leftApplicable, leftMatches
		}
		rightMatch, rightApplicable, rightMatches := evalBranchForEvidence(b.R, event, negated, meta)
		return rightMatch, leftApplicable || rightApplicable, rightMatches
	case sigmaengine.NodeOr:
		leftMatch, leftApplicable, leftMatches := evalBranchForEvidence(b.L, event, negated, meta)
		if leftMatch {
			return true, leftApplicable, leftMatches
		}
		rightMatch, rightApplicable, rightMatches := evalBranchForEvidence(b.R, event, negated, meta)
		return rightMatch, leftApplicable || rightApplicable, rightMatches
	case *sigmaengine.NodeNot:
		match, applicable, _ := evalBranchForEvidence(b.B, event, !negated, meta)
		if !applicable {
			return match, false, nil
		}
		return !match, true, nil
	case sigmaengine.NodeNot:
		match, applicable, _ := evalBranchForEvidence(b.B, event, !negated, meta)
		if !applicable {
			return match, false, nil
		}
		return !match, true, nil
	case *sigmaengine.Selection:
		match, applicable := b.Match(event)
		if !match || !applicable || negated {
			return match, applicable, nil
		}
		return true, true, collectSelectionEvidence(*b, event, meta)
	case sigmaengine.Selection:
		match, applicable := b.Match(event)
		if !match || !applicable || negated {
			return match, applicable, nil
		}
		return true, true, collectSelectionEvidence(b, event, meta)
	default:
		match, applicable := branch.Match(event)
		if !match || !applicable || negated {
			return match, applicable, nil
		}
		return match, applicable, nil
	}
}

func collectSelectionEvidence(sel sigmaengine.Selection, event sigmaengine.Event, meta ruleMetadata) []fieldPatternMatch {
	matches := make([]fieldPatternMatch, 0)

	for _, item := range sel.S {
		rawValue, ok := event.Select(item.Key)
		if !ok {
			continue
		}
		value, ok := selectionStringValue(rawValue)
		if !ok || !item.Pattern.StringMatch(value) {
			continue
		}

		patterns := meta.matchingRulePatterns(item.Key, value)
		if len(patterns) == 0 {
			patterns = describeStringMatcherPatterns(item.Pattern, value)
		}
		for _, pattern := range patterns {
			matches = append(matches, fieldPatternMatch{
				Field:   item.Key,
				Pattern: pattern,
			})
		}
	}

	for _, item := range sel.N {
		rawValue, ok := event.Select(item.Key)
		if !ok {
			continue
		}
		value, ok := selectionIntValue(rawValue)
		if !ok || !item.Pattern.NumMatch(value) {
			continue
		}

		patterns := meta.matchingRulePatterns(item.Key, strconv.Itoa(value))
		if len(patterns) == 0 {
			patterns = describeNumMatcherPatterns(item.Pattern, value)
		}
		for _, pattern := range patterns {
			matches = append(matches, fieldPatternMatch{
				Field:   item.Key,
				Pattern: pattern,
			})
		}
	}

	return matches
}

func selectionStringValue(value interface{}) (string, bool) {
	switch vt := value.(type) {
	case string:
		return vt, true
	case float64:
		return strconv.Itoa(int(vt)), true
	case int:
		return strconv.Itoa(vt), true
	case int32:
		return strconv.Itoa(int(vt)), true
	case int64:
		return strconv.Itoa(int(vt)), true
	case uint:
		return strconv.Itoa(int(vt)), true
	case uint32:
		return strconv.Itoa(int(vt)), true
	case uint64:
		return strconv.Itoa(int(vt)), true
	default:
		return "", false
	}
}

func selectionIntValue(value interface{}) (int, bool) {
	switch vt := value.(type) {
	case string:
		n, err := strconv.Atoi(vt)
		if err != nil {
			return 0, false
		}
		return n, true
	case float64:
		return int(vt), true
	case int:
		return vt, true
	case int32:
		return int(vt), true
	case int64:
		return int(vt), true
	case uint:
		return int(vt), true
	case uint32:
		return int(vt), true
	case uint64:
		return int(vt), true
	default:
		return 0, false
	}
}

func (m ruleMetadata) matchingRulePatterns(field, eventValue string) []string {
	if len(m.FieldPatterns) == 0 {
		return nil
	}
	candidates := m.FieldPatterns[strings.ToLower(strings.TrimSpace(field))]
	if len(candidates) == 0 {
		return nil
	}

	out := make([]string, 0)
	for _, candidate := range candidates {
		if candidate.matches(eventValue) {
			out = append(out, candidate.Pattern)
		}
	}
	return uniqueStrings(out)
}

func (p ruleFieldPattern) matches(eventValue string) bool {
	if p.Matcher == nil {
		return false
	}
	return p.Matcher.StringMatch(eventValue)
}

func describeStringMatcherPatterns(matcher sigmaengine.StringMatcher, value string) []string {
	switch cur := matcher.(type) {
	case sigmaengine.ContentPattern:
		if cur.StringMatch(value) {
			return []string{cur.Token}
		}
	case sigmaengine.PrefixPattern:
		if cur.StringMatch(value) {
			return []string{cur.Token + "*"}
		}
	case sigmaengine.SuffixPattern:
		if cur.StringMatch(value) {
			return []string{"*" + cur.Token}
		}
	case sigmaengine.RegexPattern:
		if cur.StringMatch(value) {
			return []string{"/" + cur.Re.String() + "/"}
		}
	case sigmaengine.StringMatchers:
		out := make([]string, 0)
		for _, inner := range cur {
			out = append(out, describeStringMatcherPatterns(inner, value)...)
		}
		return uniqueStrings(out)
	case sigmaengine.StringMatchersConj:
		out := make([]string, 0)
		for _, inner := range cur {
			out = append(out, describeStringMatcherPatterns(inner, value)...)
		}
		return uniqueStrings(out)
	case sigmaengine.GlobPattern:
		if cur.StringMatch(value) {
			return []string{"<glob>"}
		}
	default:
		if matcher.StringMatch(value) {
			return []string{"<pattern>"}
		}
	}
	return nil
}

func describeNumMatcherPatterns(matcher sigmaengine.NumMatcher, value int) []string {
	switch cur := matcher.(type) {
	case sigmaengine.NumPattern:
		if cur.NumMatch(value) {
			return []string{strconv.Itoa(cur.Val)}
		}
	case sigmaengine.NumMatchers:
		out := make([]string, 0)
		for _, inner := range cur {
			out = append(out, describeNumMatcherPatterns(inner, value)...)
		}
		return uniqueStrings(out)
	default:
		if matcher.NumMatch(value) {
			return []string{strconv.Itoa(value)}
		}
	}
	return nil
}

func formatMatchEvidence(matches []fieldPatternMatch) ([]string, map[string][]string, []string) {
	if len(matches) == 0 {
		return nil, nil, nil
	}

	detailMap := make(map[string][]string)
	for _, match := range matches {
		field := strings.TrimSpace(match.Field)
		pattern := match.Pattern
		if field == "" || pattern == "" {
			continue
		}
		detailMap[field] = append(detailMap[field], pattern)
	}
	if len(detailMap) == 0 {
		return nil, nil, nil
	}

	fields := make([]string, 0, len(detailMap))
	matchStrings := make([]string, 0)
	for field, patterns := range detailMap {
		fields = append(fields, field)
		patterns = uniqueStrings(patterns)
		detailMap[field] = patterns
		for _, pattern := range patterns {
			matchStrings = append(matchStrings, fmt.Sprintf("'%s' in %s", strings.ReplaceAll(pattern, "'", "\\'"), field))
		}
	}
	sort.Strings(fields)
	sort.Strings(matchStrings)
	return fields, detailMap, matchStrings
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func extractDetectionFieldPatterns(detection sigmaengine.Detection, noCollapseWS bool) map[string][]ruleFieldPattern {
	if len(detection) == 0 {
		return nil
	}

	out := make(map[string][]ruleFieldPattern)
	for key, value := range detection {
		if strings.EqualFold(key, "condition") {
			continue
		}
		collectFieldPatternsFromSelectionValue(out, value, noCollapseWS)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectFieldPatternsFromSelectionValue(dst map[string][]ruleFieldPattern, value interface{}, noCollapseWS bool) {
	switch cur := value.(type) {
	case map[string]interface{}:
		for selector, patternValue := range cur {
			collectFieldPatternEntry(dst, selector, patternValue, noCollapseWS)
		}
	case map[interface{}]interface{}:
		for rawSelector, patternValue := range cur {
			selector, ok := rawSelector.(string)
			if !ok {
				continue
			}
			collectFieldPatternEntry(dst, selector, patternValue, noCollapseWS)
		}
	case []interface{}:
		for _, inner := range cur {
			collectFieldPatternsFromSelectionValue(dst, inner, noCollapseWS)
		}
	}
}

func collectFieldPatternEntry(dst map[string][]ruleFieldPattern, selector string, value interface{}, noCollapseWS bool) {
	field, modifiers := parseFieldSelector(selector)
	if field == "" {
		collectFieldPatternsFromSelectionValue(dst, value, noCollapseWS)
		return
	}

	appendPattern := func(pattern string) {
		if pattern == "" {
			return
		}
		key := strings.ToLower(field)
		dst[key] = append(dst[key], newRuleFieldPattern(modifiers, pattern, noCollapseWS))
	}

	switch cur := value.(type) {
	case string:
		appendPattern(cur)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
		appendPattern(fmt.Sprint(cur))
	case []string:
		for _, item := range cur {
			appendPattern(item)
		}
	case []interface{}:
		for _, item := range cur {
			switch inner := item.(type) {
			case map[string]interface{}, map[interface{}]interface{}, []interface{}:
				collectFieldPatternsFromSelectionValue(dst, inner, noCollapseWS)
			default:
				appendPattern(fmt.Sprint(inner))
			}
		}
	case map[string]interface{}, map[interface{}]interface{}:
		collectFieldPatternsFromSelectionValue(dst, cur, noCollapseWS)
	}
}

func newRuleFieldPattern(modifiers []string, pattern string, noCollapseWS bool) ruleFieldPattern {
	p := ruleFieldPattern{
		Modifiers: append([]string(nil), modifiers...),
		Pattern:   pattern,
	}

	modifier, all := textPatternFromModifiers(modifiers)
	matcher, err := sigmaengine.NewStringMatcher(modifier, false, all, noCollapseWS, pattern)
	if err == nil {
		p.Matcher = matcher
	}
	return p
}

func textPatternFromModifiers(modifiers []string) (sigmaengine.TextPatternModifier, bool) {
	modifier := sigmaengine.TextPatternNone
	all := false
	for _, cur := range modifiers {
		switch strings.ToLower(strings.TrimSpace(cur)) {
		case "contains":
			modifier = sigmaengine.TextPatternContains
		case "startswith":
			modifier = sigmaengine.TextPatternPrefix
		case "endswith":
			modifier = sigmaengine.TextPatternSuffix
		case "re":
			modifier = sigmaengine.TextPatternRegex
		case "all":
			all = true
		}
	}
	return modifier, all
}

func parseFieldSelector(selector string) (string, []string) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", nil
	}
	bits := strings.Split(selector, "|")
	field := strings.TrimSpace(bits[0])
	if field == "" {
		return "", nil
	}
	modifiers := make([]string, 0, len(bits)-1)
	for _, modifier := range bits[1:] {
		modifier = strings.TrimSpace(modifier)
		if modifier == "" {
			continue
		}
		modifiers = append(modifiers, modifier)
	}
	return field, modifiers
}

func readRuleDateMetadata(path string) (string, string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", ""
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}

	meta := make(map[string]interface{})
	if err := yaml.Unmarshal(raw, &meta); err != nil {
		return "", ""
	}

	return stringifyRuleMetadataValue(meta["date"]), stringifyRuleMetadataValue(meta["modified"])
}

func stringifyRuleMetadataValue(value interface{}) string {
	switch cur := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(cur)
	case time.Time:
		return cur.Format("2006-01-02")
	default:
		return strings.TrimSpace(fmt.Sprint(cur))
	}
}
