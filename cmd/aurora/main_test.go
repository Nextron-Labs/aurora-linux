package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nextron-Labs/aurora-linux/cmd/aurora/agent"
	"github.com/spf13/pflag"
)

func TestWriteCLIErrorJSON(t *testing.T) {
	var out bytes.Buffer
	writeCLIError(errors.New("boom"), true, &out)

	line := strings.TrimSpace(out.String())
	if line == "" {
		t.Fatal("expected JSON output, got empty string")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %q: %v", line, err)
	}
	if got, _ := payload["message"].(string); got != "boom" {
		t.Fatalf("message = %q, want boom", got)
	}
	if got, _ := payload["level"].(string); got != "error" {
		t.Fatalf("level = %q, want error", got)
	}
	if _, ok := payload["timestamp"].(string); !ok {
		t.Fatalf("timestamp missing or not string: %#v", payload["timestamp"])
	}
}

func TestWriteCLIErrorText(t *testing.T) {
	var out bytes.Buffer
	writeCLIError(errors.New("boom"), false, &out)

	if got := out.String(); got != "boom\n" {
		t.Fatalf("text output = %q, want %q", got, "boom\n")
	}
}

func TestApplyCLIOverrides(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var cli agent.Parameters
	flags.StringSliceVar(&cli.RuleDirs, "rules", nil, "")
	flags.StringVar(&cli.FilenameIOCPath, "filename-iocs", "", "")
	flags.StringVar(&cli.C2IOCPath, "c2-iocs", "", "")
	flags.StringVar(&cli.LogFile, "logfile", "", "")
	flags.BoolVar(&cli.NoStdout, "no-stdout", false, "")
	flags.StringVar(&cli.TCPTarget, "tcp-target", "", "")
	flags.BoolVar(&cli.SigmaNoCollapseWS, "sigma-no-collapse-ws", false, "")
	flags.StringVar(&cli.PprofListen, "pprof-listen", "", "")

	if err := flags.Parse([]string{
		"--rules", "/tmp/cli-rules",
		"--filename-iocs", "/tmp/filename-iocs.txt",
		"--c2-iocs", "/tmp/c2-iocs.txt",
		"--no-stdout",
		"--tcp-target", "127.0.0.1:1514",
		"--sigma-no-collapse-ws",
		"--pprof-listen", "127.0.0.1:6060",
	}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	dst := agent.DefaultParameters()
	dst.RuleDirs = []string{filepath.Join("/tmp", "config-rules")}
	dst.LogFile = "/tmp/from-config.log"

	applyCLIOverrides(flags, &dst, cli)

	if len(dst.RuleDirs) != 1 || dst.RuleDirs[0] != "/tmp/cli-rules" {
		t.Fatalf("RuleDirs = %#v, want CLI value", dst.RuleDirs)
	}
	if !dst.NoStdout {
		t.Fatal("NoStdout should be overridden from CLI")
	}
	if dst.FilenameIOCPath != "/tmp/filename-iocs.txt" {
		t.Fatalf("FilenameIOCPath = %q, want CLI value", dst.FilenameIOCPath)
	}
	if dst.C2IOCPath != "/tmp/c2-iocs.txt" {
		t.Fatalf("C2IOCPath = %q, want CLI value", dst.C2IOCPath)
	}
	if dst.TCPTarget != "127.0.0.1:1514" {
		t.Fatalf("TCPTarget = %q, want CLI value", dst.TCPTarget)
	}
	if !dst.SigmaNoCollapseWS {
		t.Fatal("SigmaNoCollapseWS should be overridden from CLI")
	}
	if dst.PprofListen != "127.0.0.1:6060" {
		t.Fatalf("PprofListen = %q, want CLI value", dst.PprofListen)
	}
	if dst.LogFile != "/tmp/from-config.log" {
		t.Fatalf("LogFile should remain config value when CLI flag unchanged, got %q", dst.LogFile)
	}
}

func TestApplyCLIOverridesAllowsDisablingSigmaNoCollapseWS(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var cli agent.Parameters
	cli.SigmaNoCollapseWS = true
	flags.BoolVar(&cli.SigmaNoCollapseWS, "sigma-no-collapse-ws", true, "")

	if err := flags.Parse([]string{"--sigma-no-collapse-ws=false"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	dst := agent.DefaultParameters()
	if !dst.SigmaNoCollapseWS {
		t.Fatal("precondition failed: default SigmaNoCollapseWS should be true")
	}

	applyCLIOverrides(flags, &dst, cli)

	if dst.SigmaNoCollapseWS {
		t.Fatal("SigmaNoCollapseWS should be overridden to false from CLI")
	}
}
