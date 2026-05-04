package syslog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sigmaconsumer "github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

// TestCopyFailSigmaRuleMatches loads the CVE-2026-31431 (Copy Fail) sigma
// rule from the user's brief, drives the syslog provider over the sample
// log lines, and verifies the rule fires on every malicious entry.
//
// This is the real end-to-end check that the syslog provider is wired up
// in a way that sigma rules with logsource service: syslog can match it.
func TestCopyFailSigmaRuleMatches(t *testing.T) {
	ruleDir := t.TempDir()
	rulePath := filepath.Join(ruleDir, "cve-2026-31431.yml")
	if err := os.WriteFile(rulePath, []byte(copyFailSigmaRule), 0644); err != nil {
		t.Fatalf("writing rule: %v", err)
	}

	logFile := filepath.Join(t.TempDir(), "syslog")
	if err := os.WriteFile(logFile, []byte(sampleSyslog), 0644); err != nil {
		t.Fatalf("writing log: %v", err)
	}

	var buf bytes.Buffer
	matchLogger := log.New()
	matchLogger.SetOutput(&buf)
	matchLogger.SetFormatter(&log.JSONFormatter{
		DisableTimestamp:  true,
		DisableHTMLEscape: true,
	})

	consumer := sigmaconsumer.New(sigmaconsumer.Config{
		Logger:   matchLogger,
		MinLevel: "info",
	})
	if err := consumer.Initialize(); err != nil {
		t.Fatalf("consumer Initialize: %v", err)
	}
	if err := consumer.InitializeWithRules([]string{ruleDir}); err != nil {
		t.Fatalf("loading sigma rule: %v", err)
	}

	p := NewFromFiles(logFile)
	p.SetFollow(false)
	_ = p.AddSource(SourceSyslog)
	if err := p.Initialize(); err != nil {
		t.Fatalf("provider Initialize: %v", err)
	}

	var seen int
	p.SendEvents(func(event provider.Event) {
		if err := consumer.HandleEvent(event); err != nil {
			t.Errorf("HandleEvent: %v", err)
		}
		seen++
	})

	if seen != 2 {
		t.Fatalf("got %d events from provider, want 2", seen)
	}
	if got := consumer.Matches(); got != 2 {
		t.Fatalf("got %d sigma matches, want 2 (one per malicious syslog entry)", got)
	}

	// Spot-check that the rule metadata made it into the log output.
	out := buf.String()
	if !strings.Contains(out, `"sigma_rule":"a1f4c2d7-83b5-4e90-9c12-7d3e5a8b1f06"`) {
		t.Errorf("emitted log missing rule id; got: %s", out)
	}
	if !strings.Contains(out, "CVE-2026-31431") {
		t.Errorf("emitted log missing rule title; got: %s", out)
	}
}

// TestCopyFailSigmaRuleDoesNotMatchBenign makes sure the rule doesn't fire
// on unrelated syslog noise. This guards against the keyword match being
// too loose (e.g. matching on "with NULL argv" alone).
func TestCopyFailSigmaRuleDoesNotMatchBenign(t *testing.T) {
	ruleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ruleDir, "cve-2026-31431.yml"), []byte(copyFailSigmaRule), 0644); err != nil {
		t.Fatal(err)
	}

	benign := strings.Join([]string{
		`2026-04-30T03:16:46.845745+00:00 host01 sshd[1234]: Accepted password for root from 10.0.0.1 port 22 ssh2`,
		`2026-04-30T03:16:47.000000+00:00 host01 systemd[1]: Started Daily apt download activities.`,
		`2026-04-30T03:16:48.000000+00:00 host01 cron[2345]: pam_unix(cron:session): session opened for user root by (uid=0)`,
		`2026-04-30T03:16:49.000000+00:00 host01 kernel: process 'bash' started`,
		``,
	}, "\n")
	logFile := filepath.Join(t.TempDir(), "syslog")
	if err := os.WriteFile(logFile, []byte(benign), 0644); err != nil {
		t.Fatal(err)
	}

	consumer := sigmaconsumer.New(sigmaconsumer.Config{MinLevel: "info"})
	if err := consumer.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := consumer.InitializeWithRules([]string{ruleDir}); err != nil {
		t.Fatal(err)
	}

	p := NewFromFiles(logFile)
	p.SetFollow(false)
	_ = p.AddSource(SourceSyslog)
	if err := p.Initialize(); err != nil {
		t.Fatal(err)
	}
	p.SendEvents(func(event provider.Event) {
		_ = consumer.HandleEvent(event)
	})

	if got := consumer.Matches(); got != 0 {
		t.Fatalf("got %d sigma matches on benign log, want 0", got)
	}
}
