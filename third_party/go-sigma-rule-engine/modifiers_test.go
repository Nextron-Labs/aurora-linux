// Added by Nextron Systems GmbH, 2026; not part of github.com/markuskont/go-sigma-rule-engine v0.3.0. Apache-2.0, see LICENSE.
// Tests for case-insensitive matching, the |cased modifier and the |re|i,
// |re|m, |re|s regex sub-modifiers.

package sigma

import "testing"

func TestCasedAndRegexFlagModifiers(t *testing.T) {
	tests := []struct {
		key   string
		value interface{}
		event string
		want  bool
	}{
		{"F", "Value", "VALUE", true},          // default: case-insensitive
		{"F|contains", "alu", "xVALUEx", true}, // contains
		{"F|startswith", "val", "VALUE", true}, // startswith
		{"F|endswith", "LUE", "value", true},   // endswith
		{"F", "v*E", "VALUE", true},            // wildcard
		{"F|contains", "a*u", "xALUx", true},   // contains with wildcard
		{"F", "\u212Aelvin", "kelvin", false},  // Kelvin sign is not 'k'
		// ASCII-only folding on every matcher: look-alikes never match.
		{"F|contains", "kill", "/bin/\u212Aill", false},
		{"F|contains", "k*ll", "/bin/\u212Aill", false},
		{"F", "*kill", "/bin/\u212Aill", false},
		{"F|startswith", "kill", "\u212Aill", false},
		{"F|endswith", "\u00c9", "\u00e9", false},       // no non-ASCII folding
		{"F|contains", "s", "\u017f", false},            // long s is not 's'
		{"F|contains", "\u212Aill", "/bin/kill", false}, // Kelvin sign in the rule
		{"F|contains", "\u00c9", "x\u00e9x", false},     // no non-ASCII folding
		{"F|startswith", "\u00c9", "\u00e9x", false},    // same byte length
		{"F|startswith", "\u212Aill", "kill", false},
		// Values written as /.../ are plain values, not regexes.
		{"F", "/TMP/", "/tmp/", true},
		{"F", "/tmp/", "tmp", false},
		{"F|contains", "/TMP/", "ls /tmp/x", true},
		{"F|cased", "Value", "VALUE", false},         // cased equals
		{"F|cased", "Value", "Value", true},          // cased equals, same case
		{"F|contains|cased", "Val", "xVALx", false},  // cased contains
		{"F|startswith|cased", "Val", "Value", true}, // cased startswith
		{"F|endswith|cased", "UE", "value", false},   // cased endswith
		{"F|cased", "V*e", "VALUE", false},           // cased wildcard
		{"F|re", "^val", "VALUE", false},             // regex is case-sensitive
		{"F|re|i", "^val", "VALUE", true},            // re|i
		{"F|re|i", []interface{}{"x", "^val"}, "VAL", true},
		{"F|re|s", "a.b", "a\nb", true}, // re|s: dot matches newline
		{"F|re", "a.b", "a\nb", false},
		{"F|re|m", "^b$", "a\nb", true},   // re|m: multi-line anchors
		{"F|re|i|m", "^B$", "a\nb", true}, // combined flags
	}
	for _, tt := range tests {
		sel, err := newSelectionFromMap(map[string]interface{}{tt.key: tt.value}, false)
		if err != nil {
			t.Fatalf("%s: %v", tt.key, err)
		}
		got, _ := sel.Match(fieldEvent{"F": tt.event})
		if got != tt.want {
			t.Errorf("%s=%v on %q: got %v want %v", tt.key, tt.value, tt.event, got, tt.want)
		}
	}
}

func TestRegexFlagsRequireRe(t *testing.T) {
	for _, key := range []string{"F|i", "F|contains|i", "F|x", "F|re|x"} {
		if _, err := newSelectionFromMap(map[string]interface{}{key: "v"}, false); err == nil {
			t.Errorf("%s: expected an error", key)
		}
	}
}

func TestKeywordsAreCaseInsensitive(t *testing.T) {
	tests := []struct {
		keyword interface{}
		msg     string
		want    bool
	}{
		{[]interface{}{"Marker"}, "a MARKER here", true},
		{[]string{"Marker"}, "a MARKER here", true},
		{[]interface{}{"m*KER"}, "a marker here", true},
		{[]interface{}{"kill"}, "/bin/\u212Aill", false}, // Kelvin sign
		{[]interface{}{"5<>/DEV/TCP/"}, "exec 5<>/dev/tcp/1.2.3.4/80", true},
		{[]interface{}{"/bin/bash -c exec 5<>/dev/tcp/"}, "/BIN/BASH -c exec 5<>/dev/tcp/x", true},
		{[]interface{}{"/tmp/"}, "ls tmp", false}, // not a regex
	}
	for _, tt := range tests {
		k, err := NewKeyword(tt.keyword, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := k.Match(fieldEvent{"_kw": tt.msg}); got != tt.want {
			t.Errorf("keyword %v on %q: got %v want %v", tt.keyword, tt.msg, got, tt.want)
		}
	}
}

type fieldEvent map[string]interface{}

func (e fieldEvent) Keywords() ([]string, bool) {
	v, ok := e["_kw"].(string)
	if !ok {
		return nil, false
	}
	return []string{v}, true
}

func (e fieldEvent) Select(k string) (interface{}, bool) {
	v, ok := e[k]
	return v, ok
}
