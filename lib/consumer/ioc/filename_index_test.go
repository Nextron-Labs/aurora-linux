package ioc

import (
	"slices"
	"strings"
	"testing"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
)

const realFilenameIOCs = "../../../resources/iocs/filename-iocs.txt"

func longExecEvent() *testEvent {
	f := enrichment.DataFieldsMap{}
	f.AddField("Image", "/usr/bin/bash")
	f.AddField("ParentImage", "/usr/lib/systemd/systemd")
	f.AddField("CommandLine", "/bin/bash -c source /home/user/.cache/snapshot.sh 2>/dev/null || true && "+
		strings.Repeat("eval 'cd /home/user/project; go build ./... && go vet ./...' ", 30))
	f.AddField("ParentCommandLine", "/usr/lib/systemd/systemd --user")
	return &testEvent{fields: f}
}

// The index may only skip regexes that cannot match.
func TestFilenameIndexNeverSkipsAMatch(t *testing.T) {
	entries, err := loadFilenameIOCs(realFilenameIOCs, true)
	if err != nil {
		t.Fatal(err)
	}
	idx := newFilenameIndex(entries)
	isCand := func(v string, i int) bool {
		c, all := idx.candidates(v, nil)
		return all || slices.Contains(c, i)
	}
	// Per entry: values built around its literal, in several casings.
	checked := 0
	for i, e := range entries {
		for _, lit := range requiredLiterals(e.rawPattern) {
			for _, v := range []string{lit, "/x/" + strings.ToUpper(lit), "C:\\" + lit + ".exe", "/tmp/" + lit} {
				if e.pattern.MatchString(v) {
					checked++
					if !isCand(v, i) {
						t.Fatalf("entry %d %q matches %q but is not a candidate", i, e.rawPattern, v)
					}
				}
			}
		}
	}
	// Realistic values against every entry.
	values := []string{
		longExecEvent().Value("CommandLine").String,
		`C:\Windows\System32\svcstat.exe`, `\Windows\System32\wshnetc.dll`, `/tmp/shell.txt`, `/TMP/SHELL.TXT`,
		`C:\a.exe`, `C:\Users\bob\x.exe`, `\svchöst.exe`, "naïve\\msdcsvc.dat",
	}
	for _, v := range values {
		for i, e := range entries {
			if e.pattern.MatchString(v) {
				checked++
				if !isCand(v, i) {
					t.Fatalf("entry %d %q matches %q but is not a candidate", i, e.rawPattern, v)
				}
			}
		}
	}
	if checked < len(entries)/2 {
		t.Fatalf("only %d positive cases exercised", checked)
	}
	if len(idx.always) > len(entries)/50 {
		t.Fatalf("%d of %d entries have no literal: index ineffective", len(idx.always), len(entries))
	}
}

func TestRequiredLiteral(t *testing.T) {
	for pat, want := range map[string]string{
		`\\msdcsvc\.dat`:            `\msdcsvc.dat`,
		`(?i)/TMP/Shell\.txt`:       `/tmp/shell.txt`,
		`\\Windows\\(a|b)\\x\.exe$`: `\windows\`,
		`(foo|bar)`:                 ``, // two literals: see TestRequiredLiteralSets
		`(abcd)+x`:                  `abcd`,
		`a?bcd`:                     `bcd`,
		`\\svchöst\.exe`:            ``, // non-ASCII: always evaluated
	} {
		if got := requiredLiteral(pat); got != want {
			t.Errorf("requiredLiteral(%q) = %q, want %q", pat, got, want)
		}
	}
}

func TestRequiredLiteralSets(t *testing.T) {
	for pat, want := range map[string][]string{
		`\\[0-9]\.(exe|dll)$`:                    []string{"dll", "exe"},
		`(?i)\\(Users|Documents and Settings)\\`: []string{"documents and settings", "users"},
		`(a|bcd)`:                                nil, // "a" is too short to index
		`\\[0-9]{8,20}\.(aspx|asp|jsp)`:          []string{"asp", "jsp"},
	} {
		if got := requiredLiterals(pat); !slices.Equal(got, want) {
			t.Errorf("requiredLiterals(%q) = %q, want %q", pat, got, want)
		}
	}
}

func BenchmarkFilenameIOCsLongExecEvent(b *testing.B) {
	entries, err := loadFilenameIOCs(realFilenameIOCs, true)
	if err != nil {
		b.Fatal(err)
	}
	c := &Consumer{filenameEntries: entries}
	ev := longExecEvent()
	_ = c.HandleEvent(ev) // builds the index
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.HandleEvent(ev)
	}
}
