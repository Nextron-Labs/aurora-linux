package sigma

import (
	"sort"
	"testing"

	sigmaengine "github.com/markuskont/go-sigma-rule-engine"
)

func TestParseFieldSelector(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantField  string
		wantMods   []string
	}{
		{name: "simple_field", input: "Image", wantField: "Image", wantMods: nil},
		{name: "endswith", input: "Image|endswith", wantField: "Image", wantMods: []string{"endswith"}},
		{name: "contains_all", input: "CommandLine|contains|all", wantField: "CommandLine", wantMods: []string{"contains", "all"}},
		{name: "re_modifier", input: "Image|re", wantField: "Image", wantMods: []string{"re"}},
		{name: "empty_string", input: "", wantField: "", wantMods: nil},
		{name: "only_pipe", input: "|", wantField: "", wantMods: nil},
		{name: "whitespace", input: "  Image | endswith  ", wantField: "Image", wantMods: []string{"endswith"}},
		{name: "double_pipe_empty_mod", input: "Image||endswith", wantField: "Image", wantMods: []string{"endswith"}},
		{name: "startswith", input: "ParentImage|startswith", wantField: "ParentImage", wantMods: []string{"startswith"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			field, mods := parseFieldSelector(tc.input)
			if field != tc.wantField {
				t.Fatalf("field = %q, want %q", field, tc.wantField)
			}
			if len(mods) == 0 && len(tc.wantMods) == 0 {
				return // both empty/nil
			}
			if len(mods) != len(tc.wantMods) {
				t.Fatalf("modifiers = %v, want %v", mods, tc.wantMods)
			}
			for i := range mods {
				if mods[i] != tc.wantMods[i] {
					t.Fatalf("modifiers[%d] = %q, want %q", i, mods[i], tc.wantMods[i])
				}
			}
		})
	}
}

func TestExtractDetectionFieldPatternsBasic(t *testing.T) {
	detection := sigmaengine.Detection{
		"selection": map[string]interface{}{
			"Image|endswith":         "/whoami",
			"CommandLine|contains":   " /all",
		},
		"condition": "selection",
	}

	result := extractDetectionFieldPatterns(detection, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	imagePatterns := result["image"]
	if len(imagePatterns) != 1 {
		t.Fatalf("expected 1 Image pattern, got %d", len(imagePatterns))
	}
	if imagePatterns[0].Pattern != "/whoami" {
		t.Fatalf("Image pattern = %q, want /whoami", imagePatterns[0].Pattern)
	}
	if len(imagePatterns[0].Modifiers) != 1 || imagePatterns[0].Modifiers[0] != "endswith" {
		t.Fatalf("Image modifiers = %v, want [endswith]", imagePatterns[0].Modifiers)
	}

	cmdPatterns := result["commandline"]
	if len(cmdPatterns) != 1 {
		t.Fatalf("expected 1 CommandLine pattern, got %d", len(cmdPatterns))
	}
	if cmdPatterns[0].Pattern != " /all" {
		t.Fatalf("CommandLine pattern = %q, want ' /all'", cmdPatterns[0].Pattern)
	}
}

func TestExtractDetectionFieldPatternsMultipleValues(t *testing.T) {
	detection := sigmaengine.Detection{
		"selection": map[string]interface{}{
			"Image|endswith": []interface{}{"/curl", "/wget", "/nc"},
		},
		"condition": "selection",
	}

	result := extractDetectionFieldPatterns(detection, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	patterns := result["image"]
	if len(patterns) != 3 {
		t.Fatalf("expected 3 Image patterns, got %d", len(patterns))
	}
	names := make([]string, len(patterns))
	for i, p := range patterns {
		names[i] = p.Pattern
	}
	sort.Strings(names)
	want := []string{"/curl", "/nc", "/wget"}
	for i := range names {
		if names[i] != want[i] {
			t.Fatalf("pattern %d = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestExtractDetectionFieldPatternsSkipsCondition(t *testing.T) {
	detection := sigmaengine.Detection{
		"condition": "selection",
	}
	result := extractDetectionFieldPatterns(detection, false)
	if result != nil {
		t.Fatalf("expected nil for condition-only detection, got %v", result)
	}
}

func TestExtractDetectionFieldPatternsEmpty(t *testing.T) {
	result := extractDetectionFieldPatterns(nil, false)
	if result != nil {
		t.Fatalf("expected nil for nil detection, got %v", result)
	}

	result = extractDetectionFieldPatterns(sigmaengine.Detection{}, false)
	if result != nil {
		t.Fatalf("expected nil for empty detection, got %v", result)
	}
}

func TestExtractDetectionFieldPatternsListOfMaps(t *testing.T) {
	// Some Sigma rules use list of maps in detection (OR of maps).
	detection := sigmaengine.Detection{
		"selection": []interface{}{
			map[string]interface{}{"Image|endswith": "/curl"},
			map[string]interface{}{"Image|endswith": "/wget"},
		},
		"condition": "selection",
	}

	result := extractDetectionFieldPatterns(detection, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	patterns := result["image"]
	if len(patterns) != 2 {
		t.Fatalf("expected 2 Image patterns, got %d", len(patterns))
	}
}

func TestFormatMatchEvidenceBasic(t *testing.T) {
	matches := []fieldPatternMatch{
		{Field: "Image", Pattern: "/whoami"},
		{Field: "CommandLine", Pattern: " /all"},
	}

	fields, details, matchStrings := formatMatchEvidence(matches)

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}
	// fields should be sorted
	if fields[0] != "CommandLine" || fields[1] != "Image" {
		t.Fatalf("fields = %v, want [CommandLine Image]", fields)
	}

	if imgPats, ok := details["Image"]; !ok || len(imgPats) != 1 || imgPats[0] != "/whoami" {
		t.Fatalf("Image details = %v, want [/whoami]", details["Image"])
	}
	if cmdPats, ok := details["CommandLine"]; !ok || len(cmdPats) != 1 || cmdPats[0] != " /all" {
		t.Fatalf("CommandLine details = %v, want [ /all]", details["CommandLine"])
	}

	if len(matchStrings) != 2 {
		t.Fatalf("expected 2 matchStrings, got %d", len(matchStrings))
	}
	strSet := make(map[string]bool)
	for _, s := range matchStrings {
		strSet[s] = true
	}
	if !strSet["' /all' in CommandLine"] {
		t.Fatalf("missing CommandLine match string, got %v", matchStrings)
	}
	if !strSet["'/whoami' in Image"] {
		t.Fatalf("missing Image match string, got %v", matchStrings)
	}
}

func TestFormatMatchEvidenceEmpty(t *testing.T) {
	fields, details, matchStrings := formatMatchEvidence(nil)
	if fields != nil || details != nil || matchStrings != nil {
		t.Fatal("expected all nil for empty input")
	}

	fields, details, matchStrings = formatMatchEvidence([]fieldPatternMatch{})
	if fields != nil || details != nil || matchStrings != nil {
		t.Fatal("expected all nil for empty slice")
	}
}

func TestFormatMatchEvidenceDeduplicates(t *testing.T) {
	matches := []fieldPatternMatch{
		{Field: "Image", Pattern: "/whoami"},
		{Field: "Image", Pattern: "/whoami"},
		{Field: "Image", Pattern: "/whoami"},
	}

	fields, details, matchStrings := formatMatchEvidence(matches)

	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if imgPats := details["Image"]; len(imgPats) != 1 {
		t.Fatalf("expected 1 deduplicated pattern, got %d", len(imgPats))
	}
	if len(matchStrings) != 1 {
		t.Fatalf("expected 1 deduplicated matchString, got %d", len(matchStrings))
	}
}

func TestFormatMatchEvidenceSkipsEmptyFieldsAndPatterns(t *testing.T) {
	matches := []fieldPatternMatch{
		{Field: "", Pattern: "/whoami"},
		{Field: "Image", Pattern: ""},
		{Field: "", Pattern: ""},
	}

	fields, details, matchStrings := formatMatchEvidence(matches)
	if fields != nil || details != nil || matchStrings != nil {
		t.Fatal("expected all nil when all entries have empty field or pattern")
	}
}

func TestFormatMatchEvidenceEscapesSingleQuotes(t *testing.T) {
	matches := []fieldPatternMatch{
		{Field: "CommandLine", Pattern: "it's a test"},
	}

	_, _, matchStrings := formatMatchEvidence(matches)
	if len(matchStrings) != 1 {
		t.Fatalf("expected 1 matchString, got %d", len(matchStrings))
	}
	if matchStrings[0] != `'it\'s a test' in CommandLine` {
		t.Fatalf("matchString = %q, want escaped quotes", matchStrings[0])
	}
}

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "nil", input: nil, want: nil},
		{name: "empty", input: []string{}, want: nil},
		{name: "no_dupes", input: []string{"b", "a"}, want: []string{"a", "b"}},
		{name: "with_dupes", input: []string{"a", "b", "a", "c", "b"}, want: []string{"a", "b", "c"}},
		{name: "empty_strings_filtered", input: []string{"", "a", "", "b"}, want: []string{"a", "b"}},
		{name: "all_empty", input: []string{"", "", ""}, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := uniqueStrings(tc.input)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("uniqueStrings() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("uniqueStrings()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestTextPatternFromModifiers(t *testing.T) {
	tests := []struct {
		name     string
		mods     []string
		wantMod  sigmaengine.TextPatternModifier
		wantAll  bool
	}{
		{name: "empty", mods: nil, wantMod: sigmaengine.TextPatternNone, wantAll: false},
		{name: "contains", mods: []string{"contains"}, wantMod: sigmaengine.TextPatternContains, wantAll: false},
		{name: "endswith", mods: []string{"endswith"}, wantMod: sigmaengine.TextPatternSuffix, wantAll: false},
		{name: "startswith", mods: []string{"startswith"}, wantMod: sigmaengine.TextPatternPrefix, wantAll: false},
		{name: "re", mods: []string{"re"}, wantMod: sigmaengine.TextPatternRegex, wantAll: false},
		{name: "contains_all", mods: []string{"contains", "all"}, wantMod: sigmaengine.TextPatternContains, wantAll: true},
		{name: "case_insensitive", mods: []string{"CONTAINS"}, wantMod: sigmaengine.TextPatternContains, wantAll: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod, all := textPatternFromModifiers(tc.mods)
			if mod != tc.wantMod {
				t.Fatalf("modifier = %v, want %v", mod, tc.wantMod)
			}
			if all != tc.wantAll {
				t.Fatalf("all = %v, want %v", all, tc.wantAll)
			}
		})
	}
}

func TestSelectionStringValue(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantStr string
		wantOK  bool
	}{
		{name: "string", input: "hello", wantStr: "hello", wantOK: true},
		{name: "float64", input: float64(42), wantStr: "42", wantOK: true},
		{name: "int", input: 7, wantStr: "7", wantOK: true},
		{name: "int64", input: int64(99), wantStr: "99", wantOK: true},
		{name: "uint32", input: uint32(10), wantStr: "10", wantOK: true},
		{name: "nil", input: nil, wantStr: "", wantOK: false},
		{name: "bool", input: true, wantStr: "", wantOK: false},
		{name: "slice", input: []string{"a"}, wantStr: "", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selectionStringValue(tc.input)
			if ok != tc.wantOK || got != tc.wantStr {
				t.Fatalf("selectionStringValue(%v) = (%q, %v), want (%q, %v)", tc.input, got, ok, tc.wantStr, tc.wantOK)
			}
		})
	}
}

func TestSelectionIntValue(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantInt int
		wantOK  bool
	}{
		{name: "string_num", input: "42", wantInt: 42, wantOK: true},
		{name: "string_invalid", input: "abc", wantInt: 0, wantOK: false},
		{name: "float64", input: float64(99), wantInt: 99, wantOK: true},
		{name: "int", input: 7, wantInt: 7, wantOK: true},
		{name: "int32", input: int32(10), wantInt: 10, wantOK: true},
		{name: "nil", input: nil, wantInt: 0, wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selectionIntValue(tc.input)
			if ok != tc.wantOK || got != tc.wantInt {
				t.Fatalf("selectionIntValue(%v) = (%d, %v), want (%d, %v)", tc.input, got, ok, tc.wantInt, tc.wantOK)
			}
		})
	}
}

func TestRuleLookupKey(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		title string
		want  string
	}{
		{name: "id_only", id: "abc-123", title: "", want: "abc-123"},
		{name: "title_fallback", id: "", title: "My Rule", want: "My Rule"},
		{name: "id_preferred", id: "abc", title: "My Rule", want: "abc"},
		{name: "whitespace_id", id: "  ", title: "My Rule", want: "My Rule"},
		{name: "whitespace_title", id: "", title: "  My Rule  ", want: "My Rule"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleLookupKey(tc.id, tc.title)
			if got != tc.want {
				t.Fatalf("ruleLookupKey(%q, %q) = %q, want %q", tc.id, tc.title, got, tc.want)
			}
		})
	}
}

func TestRuleMetadataMatchingRulePatterns(t *testing.T) {
	meta := ruleMetadata{
		FieldPatterns: extractDetectionFieldPatterns(sigmaengine.Detection{
			"selection": map[string]interface{}{
				"Image|endswith": "/whoami",
				"CommandLine|contains": " /all",
			},
			"condition": "selection",
		}, false),
	}

	// Should match endswith /whoami.
	got := meta.matchingRulePatterns("Image", "/usr/bin/whoami")
	if len(got) != 1 || got[0] != "/whoami" {
		t.Fatalf("matchingRulePatterns(Image) = %v, want [/whoami]", got)
	}

	// Should match contains /all.
	got = meta.matchingRulePatterns("CommandLine", "whoami /all")
	if len(got) != 1 || got[0] != " /all" {
		t.Fatalf("matchingRulePatterns(CommandLine) = %v, want [ /all]", got)
	}

	// Non-matching value.
	got = meta.matchingRulePatterns("Image", "/usr/bin/ls")
	if len(got) != 0 {
		t.Fatalf("matchingRulePatterns(non-match) = %v, want empty", got)
	}

	// Unknown field.
	got = meta.matchingRulePatterns("UnknownField", "anything")
	if len(got) != 0 {
		t.Fatalf("matchingRulePatterns(unknown) = %v, want empty", got)
	}
}

func TestRuleMetadataMatchingRulePatternsEmptyMap(t *testing.T) {
	meta := ruleMetadata{}
	got := meta.matchingRulePatterns("Image", "/usr/bin/whoami")
	if got != nil {
		t.Fatalf("expected nil for empty FieldPatterns, got %v", got)
	}
}

func TestNewRuleFieldPatternBuildsWorkingMatcher(t *testing.T) {
	// endswith modifier
	p := newRuleFieldPattern([]string{"endswith"}, "/bash", false)
	if !p.matches("/usr/bin/bash") {
		t.Fatal("expected endswith /bash to match /usr/bin/bash")
	}
	if p.matches("/usr/bin/zsh") {
		t.Fatal("expected endswith /bash to NOT match /usr/bin/zsh")
	}

	// contains modifier
	p = newRuleFieldPattern([]string{"contains"}, "evil", false)
	if !p.matches("path/to/evil/binary") {
		t.Fatal("expected contains 'evil' to match")
	}
	if p.matches("path/to/good/binary") {
		t.Fatal("expected contains 'evil' to NOT match 'good'")
	}

	// no modifier (exact match)
	p = newRuleFieldPattern(nil, "/usr/bin/whoami", false)
	if !p.matches("/usr/bin/whoami") {
		t.Fatal("expected exact match for /usr/bin/whoami")
	}
	if p.matches("/usr/bin/whoamix") {
		t.Fatal("expected exact match to NOT match suffix")
	}
}

func TestStringifyRuleMetadataValue(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{name: "nil", input: nil, want: ""},
		{name: "string", input: "2026-01-01", want: "2026-01-01"},
		{name: "string_whitespace", input: "  2026-01-01  ", want: "2026-01-01"},
		{name: "int", input: 2026, want: "2026"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stringifyRuleMetadataValue(tc.input)
			if got != tc.want {
				t.Fatalf("stringifyRuleMetadataValue(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestDescribeStringMatcherPatterns(t *testing.T) {
	// Test ContentPattern (TextPatternNone = exact match)
	contentMatcher, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternNone, false, false, false, "/usr/bin/bash")
	got := describeStringMatcherPatterns(contentMatcher, "/usr/bin/bash")
	if len(got) != 1 || got[0] != "/usr/bin/bash" {
		t.Fatalf("ContentPattern match: got %v, want [/usr/bin/bash]", got)
	}

	// Test ContentPattern non-match
	got = describeStringMatcherPatterns(contentMatcher, "/usr/bin/zsh")
	if len(got) != 0 {
		t.Fatalf("ContentPattern non-match: got %v, want []", got)
	}

	// Test PrefixPattern
	prefixMatcher, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternPrefix, false, false, false, "/usr/")
	got = describeStringMatcherPatterns(prefixMatcher, "/usr/bin/bash")
	if len(got) != 1 || got[0] != "/usr/*" {
		t.Fatalf("PrefixPattern: got %v, want [/usr/*]", got)
	}

	// Test PrefixPattern non-match
	got = describeStringMatcherPatterns(prefixMatcher, "/bin/bash")
	if len(got) != 0 {
		t.Fatalf("PrefixPattern non-match: got %v, want []", got)
	}

	// Test SuffixPattern
	suffixMatcher, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternSuffix, false, false, false, "/bash")
	got = describeStringMatcherPatterns(suffixMatcher, "/usr/bin/bash")
	if len(got) != 1 || got[0] != "*/bash" {
		t.Fatalf("SuffixPattern: got %v, want [*/bash]", got)
	}

	// Test SuffixPattern non-match
	got = describeStringMatcherPatterns(suffixMatcher, "/usr/bin/zsh")
	if len(got) != 0 {
		t.Fatalf("SuffixPattern non-match: got %v, want []", got)
	}

	// Test RegexPattern
	regexMatcher, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternRegex, false, false, false, ".*bash$")
	got = describeStringMatcherPatterns(regexMatcher, "/usr/bin/bash")
	if len(got) != 1 || got[0] != "/.*bash$/" {
		t.Fatalf("RegexPattern: got %v, want [/.*bash$/]", got)
	}

	// Test RegexPattern non-match
	got = describeStringMatcherPatterns(regexMatcher, "/usr/bin/zsh")
	if len(got) != 0 {
		t.Fatalf("RegexPattern non-match: got %v, want []", got)
	}

	// Test StringMatchers (multiple patterns OR'd together) with exact match patterns
	matcher1, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternNone, false, false, false, "test1")
	matcher2, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternNone, false, false, false, "test2")
	combined := sigmaengine.StringMatchers{matcher1, matcher2}
	// Only one should match for exact patterns
	got = describeStringMatcherPatterns(combined, "test1")
	if len(got) != 1 || got[0] != "test1" {
		t.Fatalf("StringMatchers: got %v, want [test1]", got)
	}

	// Test StringMatchersConj (multiple patterns AND'd together) with prefix patterns
	prefix1, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternPrefix, false, false, false, "/usr/")
	prefix2, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternSuffix, false, false, false, "/bash")
	conjMatcher := sigmaengine.StringMatchersConj{prefix1, prefix2}
	got = describeStringMatcherPatterns(conjMatcher, "/usr/bin/bash")
	if len(got) != 2 {
		t.Fatalf("StringMatchersConj: got %v, want 2 patterns", got)
	}

	// Test GlobPattern via NewStringMatcher (contains modifier creates glob)
	globMatcher, _ := sigmaengine.NewStringMatcher(sigmaengine.TextPatternContains, false, false, false, "evil")
	got = describeStringMatcherPatterns(globMatcher, "path/to/evil/binary")
	// GlobPattern returns "<glob>" as the description
	if len(got) != 1 || got[0] != "<glob>" {
		t.Fatalf("GlobPattern: got %v, want [<glob>]", got)
	}

	// Test GlobPattern non-match
	got = describeStringMatcherPatterns(globMatcher, "path/to/good/binary")
	if len(got) != 0 {
		t.Fatalf("GlobPattern non-match: got %v, want []", got)
	}
}

func TestDescribeNumMatcherPatterns(t *testing.T) {
	// Test NumPattern match
	numMatcher := sigmaengine.NumPattern{Val: 42}
	got := describeNumMatcherPatterns(numMatcher, 42)
	if len(got) != 1 || got[0] != "42" {
		t.Fatalf("NumPattern match: got %v, want [42]", got)
	}

	// Test NumPattern non-match
	got = describeNumMatcherPatterns(numMatcher, 99)
	if len(got) != 0 {
		t.Fatalf("NumPattern non-match: got %v, want []", got)
	}

	// Test NumMatchers (multiple patterns OR'd)
	numMatcher1 := sigmaengine.NumPattern{Val: 10}
	numMatcher2 := sigmaengine.NumPattern{Val: 20}
	combined := sigmaengine.NumMatchers{numMatcher1, numMatcher2}
	got = describeNumMatcherPatterns(combined, 10)
	if len(got) != 1 || got[0] != "10" {
		t.Fatalf("NumMatchers match: got %v, want [10]", got)
	}

	// Test NumMatchers with both matching
	got = describeNumMatcherPatterns(combined, 20)
	if len(got) != 1 || got[0] != "20" {
		t.Fatalf("NumMatchers match second: got %v, want [20]", got)
	}
}

func TestBuildRuleMetadataNilTree(t *testing.T) {
	meta := buildRuleMetadata(nil)
	if meta.ID != "" || meta.Title != "" {
		t.Fatalf("expected empty metadata for nil tree, got ID=%q Title=%q", meta.ID, meta.Title)
	}

	meta = buildRuleMetadata(&sigmaengine.Tree{Rule: nil})
	if meta.ID != "" || meta.Title != "" {
		t.Fatalf("expected empty metadata for nil rule, got ID=%q Title=%q", meta.ID, meta.Title)
	}
}

func TestRuleFieldPatternMatchesWithNilMatcher(t *testing.T) {
	p := ruleFieldPattern{
		Modifiers: []string{"contains"},
		Pattern:   "test",
		Matcher:   nil,
	}

	if p.matches("any value") {
		t.Fatal("matches() should return false for nil Matcher")
	}
}

func TestCollectFieldPatternEntryWithNumericTypes(t *testing.T) {
	dst := make(map[string][]ruleFieldPattern)

	// Test int
	collectFieldPatternEntry(dst, "EventID", 4688, false)
	if len(dst["eventid"]) != 1 || dst["eventid"][0].Pattern != "4688" {
		t.Fatalf("int pattern: got %v", dst["eventid"])
	}

	// Test float32
	dst = make(map[string][]ruleFieldPattern)
	collectFieldPatternEntry(dst, "Score", float32(3.14), false)
	if len(dst["score"]) != 1 {
		t.Fatalf("float32 pattern: got %v", dst["score"])
	}

	// Test bool
	dst = make(map[string][]ruleFieldPattern)
	collectFieldPatternEntry(dst, "Enabled", true, false)
	if len(dst["enabled"]) != 1 || dst["enabled"][0].Pattern != "true" {
		t.Fatalf("bool pattern: got %v", dst["enabled"])
	}
}

func TestCollectFieldPatternsFromSelectionValueMapInterfaceInterface(t *testing.T) {
	dst := make(map[string][]ruleFieldPattern)

	// Use map[interface{}]interface{} as YAML parsing sometimes produces this
	value := map[interface{}]interface{}{
		"Image|endswith": "/bash",
	}

	collectFieldPatternsFromSelectionValue(dst, value, false)

	if len(dst["image"]) != 1 || dst["image"][0].Pattern != "/bash" {
		t.Fatalf("map[interface{}]interface{}: got %v", dst["image"])
	}
}

func TestExtractDetectionFieldPatternsWithNestedMaps(t *testing.T) {
	detection := sigmaengine.Detection{
		"selection": []interface{}{
			map[interface{}]interface{}{
				"Image|endswith": "/curl",
			},
			map[interface{}]interface{}{
				"Image|endswith": "/wget",
			},
		},
		"condition": "selection",
	}

	result := extractDetectionFieldPatterns(detection, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	patterns := result["image"]
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(patterns))
	}
}
