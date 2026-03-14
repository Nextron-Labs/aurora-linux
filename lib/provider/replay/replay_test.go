package replay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

func TestReplayProviderRespectsSourceFilters(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")
	content := "" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"100"}` + "\n" +
		`{"_provider":"LinuxEBPF","_eventID":3,"_source":"LinuxEBPF:NetConnect","ProcessId":"200"}` + "\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path)
	if err := r.AddSource("LinuxEBPF:ProcessExec"); err != nil {
		t.Fatalf("AddSource() error = %v", err)
	}

	var events []provider.Event
	r.SendEvents(func(event provider.Event) {
		events = append(events, event)
	})

	if len(events) != 1 {
		t.Fatalf("expected 1 replayed event after source filtering, got %d", len(events))
	}
	if events[0].Source() != "LinuxEBPF:ProcessExec" {
		t.Fatalf("unexpected event source: got %q", events[0].Source())
	}
}

func TestRecordToEventParsesNumericProcessIDAndInfersSource(t *testing.T) {
	record := map[string]interface{}{
		"_provider": "LinuxEBPF",
		"_eventID":  float64(11),
		"ProcessId": float64(4321),
	}

	evt, err := recordToEvent(record)
	if err != nil {
		t.Fatalf("recordToEvent() error = %v", err)
	}

	if evt.Process() != 4321 {
		t.Fatalf("Process() = %d, want 4321", evt.Process())
	}
	if evt.Source() != "LinuxEBPF:FileCreate" {
		t.Fatalf("Source() = %q, want LinuxEBPF:FileCreate", evt.Source())
	}
}

func TestRecordToEventParsesStringEventID(t *testing.T) {
	record := map[string]interface{}{
		"_provider": "LinuxEBPF",
		"_eventID":  "3",
		"ProcessId": "55",
	}

	evt, err := recordToEvent(record)
	if err != nil {
		t.Fatalf("recordToEvent() error = %v", err)
	}

	if evt.ID().EventID != 3 {
		t.Fatalf("EventID = %d, want 3", evt.ID().EventID)
	}
}

func TestReplayProviderHandlesLargeJSONLine(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "large.jsonl")

	largeValue := strings.Repeat("A", 2*1024*1024)
	content := fmt.Sprintf(
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"42","Blob":"%s"}`+"\n",
		largeValue,
	)

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path)
	count := 0
	r.SendEvents(func(event provider.Event) {
		count++
	})

	if count != 1 {
		t.Fatalf("expected 1 replayed event for oversized JSON line, got %d", count)
	}
}

func TestReplayProviderCloseStopsPlayback(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")
	content := "" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"1"}` + "\n" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"2"}` + "\n" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"3"}` + "\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path)
	count := 0
	r.SendEvents(func(event provider.Event) {
		count++
		if count == 1 {
			if err := r.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		}
	})

	if count != 1 {
		t.Fatalf("expected replay to stop after Close(), got %d callbacks", count)
	}
}

func TestReplayProviderConcurrentAddSourceAndSendEvents(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")
	content := "" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"1"}` + "\n" +
		`{"_provider":"LinuxEBPF","_eventID":3,"_source":"LinuxEBPF:NetConnect","ProcessId":"2"}` + "\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		r.AddSource("LinuxEBPF:ProcessExec")
		r.AddSource("LinuxEBPF:NetConnect")
	}()

	go func() {
		defer wg.Done()
		r.SendEvents(func(event provider.Event) {})
	}()

	wg.Wait()
}
