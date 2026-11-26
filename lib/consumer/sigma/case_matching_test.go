package sigma

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	log "github.com/sirupsen/logrus"
)

// loadCaseTestRule loads a single process_creation rule with the given
// detection block and returns the consumer and its log output.
func loadCaseTestRule(t *testing.T, detection string) (*SigmaConsumer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	writeRuleFile(t, dir, "rule.yml", `title: Case Test
id: 6b1f0c52-7d1e-4a8e-b0f4-3c2d9e8a1f00
level: high
logsource:
  product: linux
  category: process_creation
detection:
`+detection)

	out := &bytes.Buffer{}
	logger := log.New()
	logger.SetOutput(out)
	logger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true, DisableHTMLEscape: true})

	c := New(Config{Logger: logger, MinLevel: "info"})
	if err := c.InitializeWithRules([]string{dir}); err != nil {
		t.Fatalf("InitializeWithRules() error = %v", err)
	}
	return c, out
}

func caseTestEvent(fields map[string]string) *testEvent {
	m := enrichment.DataFieldsMap{}
	for k, v := range fields {
		m[k] = enrichment.NewStringValue(v)
	}
	return &testEvent{ts: time.Unix(1700000000, 0).UTC(), fields: m}
}

func TestSigmaMatchingIsCaseInsensitive(t *testing.T) {
	tests := []struct {
		name      string
		detection string
		event     map[string]string
		want      bool
	}{
		{
			name:      "equals",
			detection: "  selection:\n    Image: '/usr/bin/WhoAmI'\n  condition: selection\n",
			event:     map[string]string{"Image": "/USR/BIN/whoami"},
			want:      true,
		},
		{
			name:      "contains",
			detection: "  selection:\n    CommandLine|contains: 'aurora-marker'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "echo AURORA-MARKER"},
			want:      true,
		},
		{
			name:      "contains all",
			detection: "  selection:\n    CommandLine|contains|all:\n      - '-Enc'\n      - 'pwsh'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "PWSH -ENC AAAA"},
			want:      true,
		},
		{
			name:      "startswith",
			detection: "  selection:\n    CommandLine|startswith: 'HTTP://'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "http://evil.example"},
			want:      true,
		},
		{
			name:      "endswith",
			detection: "  selection:\n    Image|endswith: '/Python3'\n  condition: selection\n",
			event:     map[string]string{"Image": "/usr/bin/python3"},
			want:      true,
		},
		{
			name:      "wildcard",
			detection: "  selection:\n    CommandLine: '*Union*Select*'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "mysql -e 'UNION ALL SELECT 1'"},
			want:      true,
		},
		{
			name:      "keywords",
			detection: "  keywords:\n    - 'Mimikatz'\n  condition: keywords\n",
			event:     map[string]string{"CommandLine": "./MIMIKATZ"},
			want:      true,
		},
		{
			name:      "regex stays case-sensitive",
			detection: "  selection:\n    CommandLine|re: 'abc[0-9]'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "ABC1"},
			want:      false,
		},
		{
			name:      "regex still matches its own case",
			detection: "  selection:\n    CommandLine|re: 'ABC[0-9]'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "ABC1"},
			want:      true,
		},
		{
			name:      "no unicode folding (Kelvin sign)",
			detection: "  selection:\n    Image|endswith: '/kill'\n  condition: selection\n",
			event:     map[string]string{"Image": "/usr/bin/Kill"},
			want:      false,
		},
		{
			name: "filter is case-insensitive too",
			detection: "  selection:\n    CommandLine|contains: 'marker'\n" +
				"  filter:\n    Image|endswith: '/kworker'\n" +
				"  condition: selection and not filter\n",
			event: map[string]string{"CommandLine": "marker", "Image": "/usr/bin/KWORKER"},
			want:  false,
		},
		{
			name:      "cased matches the exact case",
			detection: "  selection:\n    CommandLine|contains|cased: 'Marker'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "echo Marker"},
			want:      true,
		},
		{
			name:      "cased rejects another case",
			detection: "  selection:\n    CommandLine|contains|cased: 'Marker'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "echo MARKER"},
			want:      false,
		},
		{
			name:      "cased equals",
			detection: "  selection:\n    Image|cased: '/usr/bin/Tool'\n  condition: selection\n",
			event:     map[string]string{"Image": "/usr/bin/tool"},
			want:      false,
		},
		{
			name:      "re|i is case-insensitive",
			detection: "  selection:\n    CommandLine|re|i: 'abc[0-9]'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "ABC1"},
			want:      true,
		},
		{
			name:      "re|i with a list",
			detection: "  selection:\n    CommandLine|re|i:\n      - 'nomatch'\n      - '^curl .*HTTP://'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "CURL -s http://x"},
			want:      true,
		},
		{
			name:      "re|s lets dot match a newline",
			detection: "  selection:\n    CommandLine|re|s: 'a.b'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "a\nb"},
			want:      true,
		},
		{
			name:      "re|m anchors per line",
			detection: "  selection:\n    CommandLine|re|m: '^b$'\n  condition: selection\n",
			event:     map[string]string{"CommandLine": "a\nb"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, out := loadCaseTestRule(t, tt.detection)
			if err := c.HandleEvent(caseTestEvent(tt.event)); err != nil {
				t.Fatalf("HandleEvent() error = %v", err)
			}
			got := strings.Contains(out.String(), `"Sigma match"`)
			if got != tt.want {
				t.Fatalf("match = %v, want %v (log: %s)", got, tt.want, out.String())
			}
		})
	}
}

func TestCaseInsensitiveMatchEvidenceShowsRulePattern(t *testing.T) {
	c, out := loadCaseTestRule(t, "  selection:\n    CommandLine|contains: 'Aurora-Marker'\n  condition: selection\n")
	if err := c.HandleEvent(caseTestEvent(map[string]string{"CommandLine": "echo AURORA-MARKER"})); err != nil {
		t.Fatalf("HandleEvent() error = %v", err)
	}

	var logged map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &logged); err != nil {
		t.Fatalf("decode log: %v (%s)", err, out.String())
	}
	details, _ := logged["sigma_match_details"].(map[string]interface{})
	got := toStringSetFromAnySlice(details["CommandLine"])
	if _, ok := got["Aurora-Marker"]; !ok || len(got) != 1 {
		t.Fatalf("sigma_match_details[CommandLine] = %v, want [Aurora-Marker]", details["CommandLine"])
	}
}

// matchEvidence runs one event through a rule and returns sigma_match_details.
func matchEvidence(t *testing.T, detection string, fields map[string]string) map[string]interface{} {
	t.Helper()
	c, out := loadCaseTestRule(t, detection)
	if err := c.HandleEvent(caseTestEvent(fields)); err != nil {
		t.Fatalf("HandleEvent() error = %v", err)
	}
	var logged map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &logged); err != nil {
		t.Fatalf("decode log: %v (%s)", err, out.String())
	}
	details, _ := logged["sigma_match_details"].(map[string]interface{})
	return details
}

func TestMatchEvidenceHonorsCased(t *testing.T) {
	// The rule matches through "echo"; the |cased pattern must not be shown
	// as evidence because it does not match "MARKER".
	details := matchEvidence(t,
		"  sel1:\n    CommandLine|contains|cased: 'Marker'\n"+
			"  sel2:\n    CommandLine|contains: 'echo'\n"+
			"  condition: sel1 or sel2\n",
		map[string]string{"CommandLine": "echo MARKER"})
	got := toStringSetFromAnySlice(details["CommandLine"])
	if _, ok := got["Marker"]; ok {
		t.Fatalf("cased pattern shown as evidence: %v", details["CommandLine"])
	}
	if _, ok := got["echo"]; !ok {
		t.Fatalf("sigma_match_details[CommandLine] = %v, want echo", details["CommandLine"])
	}
}

func TestMatchEvidenceHonorsRegexFlags(t *testing.T) {
	details := matchEvidence(t,
		"  sel1:\n    CommandLine|re|i: 'marker-[0-9]+'\n"+
			"  sel2:\n    Image|endswith: '/echo'\n"+
			"  condition: sel1 or sel2\n",
		map[string]string{"CommandLine": "echo MARKER-42", "Image": "/bin/echo"})
	// Evidence shows the rule's own pattern only when matchdetails.go applies
	// the same (?i) flag as the engine; otherwise it falls back to the
	// engine's compiled regex.
	got := toStringSetFromAnySlice(details["CommandLine"])
	if _, ok := got["marker-[0-9]+"]; !ok || len(got) != 1 {
		t.Fatalf("sigma_match_details[CommandLine] = %v, want [marker-[0-9]+]", details["CommandLine"])
	}
}
