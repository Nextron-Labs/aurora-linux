package replay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
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

func TestReplayProviderNameAndDescription(t *testing.T) {
	r := New()
	if got := r.Name(); got != "Replay" {
		t.Fatalf("Name() = %q, want Replay", got)
	}
	if got := r.Description(); got != "Replay provider for pre-recorded events" {
		t.Fatalf("Description() = %q", got)
	}
}

func TestReplayProviderLostEventsAlwaysZero(t *testing.T) {
	r := New()
	if got := r.LostEvents(); got != 0 {
		t.Fatalf("LostEvents() = %d, want 0", got)
	}
}

func TestReplayProviderInitialize(t *testing.T) {
	r := New()
	if err := r.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
}

func TestReplayProviderHandlesMissingFile(t *testing.T) {
	r := New("/nonexistent/path/events.jsonl")
	count := 0
	// Should not panic, just log warning and continue
	r.SendEvents(func(event provider.Event) {
		count++
	})

	if count != 0 {
		t.Fatalf("expected 0 events from missing file, got %d", count)
	}
}

func TestReplayProviderSkipsEmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")
	content := "" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"1"}` + "\n" +
		"\n" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"2"}` + "\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path)
	count := 0
	r.SendEvents(func(event provider.Event) {
		count++
	})

	if count != 2 {
		t.Fatalf("expected 2 events (skipping empty line), got %d", count)
	}
}

func TestReplayProviderSkipsMalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")
	content := "" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"1"}` + "\n" +
		`not valid json` + "\n" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"2"}` + "\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path)
	count := 0
	r.SendEvents(func(event provider.Event) {
		count++
	})

	if count != 2 {
		t.Fatalf("expected 2 events (skipping malformed JSON), got %d", count)
	}
}

func TestReplayProviderWithNoSourceFilters(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")
	content := "" +
		`{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"1"}` + "\n" +
		`{"_provider":"LinuxEBPF","_eventID":3,"_source":"LinuxEBPF:NetConnect","ProcessId":"2"}` + "\n"

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path)
	// Don't add any source filters - should emit all events
	count := 0
	r.SendEvents(func(event provider.Event) {
		count++
	})

	if count != 2 {
		t.Fatalf("expected 2 events with no source filters, got %d", count)
	}
}

func TestReplayProviderWithMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()
	path1 := filepath.Join(tmpDir, "events1.jsonl")
	path2 := filepath.Join(tmpDir, "events2.jsonl")

	content1 := `{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"1"}` + "\n"
	content2 := `{"_provider":"LinuxEBPF","_eventID":1,"_source":"LinuxEBPF:ProcessExec","ProcessId":"2"}` + "\n"

	if err := os.WriteFile(path1, []byte(content1), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(path2, []byte(content2), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	r := New(path1, path2)
	count := 0
	r.SendEvents(func(event provider.Event) {
		count++
	})

	if count != 2 {
		t.Fatalf("expected 2 events from 2 files, got %d", count)
	}
}

func TestRecordToEventWithTimestamp(t *testing.T) {
	record := map[string]interface{}{
		"_provider":  "LinuxEBPF",
		"_eventID":   float64(1),
		"_timestamp": "2026-03-17T12:00:00Z",
		"ProcessId":  "100",
	}

	evt, err := recordToEvent(record)
	if err != nil {
		t.Fatalf("recordToEvent() error = %v", err)
	}

	if evt.Time().IsZero() {
		t.Fatal("Time() should not be zero")
	}
	if evt.Time().Year() != 2026 {
		t.Fatalf("Time().Year() = %d, want 2026", evt.Time().Year())
	}
}

func TestRecordToEventWithExplicitSource(t *testing.T) {
	record := map[string]interface{}{
		"_provider": "LinuxEBPF",
		"_eventID":  float64(1),
		"_source":   "CustomSource",
		"ProcessId": "100",
	}

	evt, err := recordToEvent(record)
	if err != nil {
		t.Fatalf("recordToEvent() error = %v", err)
	}

	if evt.Source() != "CustomSource" {
		t.Fatalf("Source() = %q, want CustomSource", evt.Source())
	}
}

func TestRecordToEventWithDefaultProvider(t *testing.T) {
	record := map[string]interface{}{
		"_eventID":  float64(1),
		"ProcessId": "100",
	}

	evt, err := recordToEvent(record)
	if err != nil {
		t.Fatalf("recordToEvent() error = %v", err)
	}

	if evt.ID().ProviderName != "LinuxEBPF" {
		t.Fatalf("ProviderName = %q, want LinuxEBPF (default)", evt.ID().ProviderName)
	}
}

func TestReplayEventMethods(t *testing.T) {
	evt := &replayEvent{
		id: provider.EventIdentifier{
			ProviderName: "TestProvider",
			EventID:      99,
		},
		pid:    12345,
		source: "TestSource",
		fields: make(enrichment.DataFieldsMap),
	}
	evt.fields.AddField("Image", "/bin/test")

	if evt.ID().ProviderName != "TestProvider" {
		t.Fatalf("ID().ProviderName = %q", evt.ID().ProviderName)
	}
	if evt.Process() != 12345 {
		t.Fatalf("Process() = %d", evt.Process())
	}
	if evt.Source() != "TestSource" {
		t.Fatalf("Source() = %q", evt.Source())
	}
	if !evt.Value("Image").Valid || evt.Value("Image").String != "/bin/test" {
		t.Fatalf("Value(Image) = %v", evt.Value("Image"))
	}

	count := 0
	evt.ForEach(func(k, v string) {
		count++
	})
	if count != 1 {
		t.Fatalf("ForEach count = %d, want 1", count)
	}

	if evt.Fields() == nil {
		t.Fatal("Fields() should not be nil")
	}
}

func TestParseEventIDInvalidString(t *testing.T) {
	// Invalid string
	got := parseEventID("invalid")
	if got != 0 {
		t.Fatalf("parseEventID(invalid) = %d, want 0", got)
	}

	// Negative float
	got = parseEventID(float64(-1))
	if got != 0 {
		t.Fatalf("parseEventID(-1) = %d, want 0", got)
	}

	// Float > MaxUint16
	got = parseEventID(float64(70000))
	if got != 0 {
		t.Fatalf("parseEventID(70000) = %d, want 0", got)
	}

	// Non-integer float
	got = parseEventID(float64(1.5))
	if got != 0 {
		t.Fatalf("parseEventID(1.5) = %d, want 0", got)
	}

	// Unknown type
	got = parseEventID([]int{1, 2, 3})
	if got != 0 {
		t.Fatalf("parseEventID(slice) = %d, want 0", got)
	}
}

func TestParseUint32Invalid(t *testing.T) {
	// Invalid string
	got, ok := parseUint32("invalid")
	if ok || got != 0 {
		t.Fatalf("parseUint32(invalid) = (%d, %v), want (0, false)", got, ok)
	}

	// Negative float
	got, ok = parseUint32(float64(-1))
	if ok || got != 0 {
		t.Fatalf("parseUint32(-1) = (%d, %v), want (0, false)", got, ok)
	}

	// Float > MaxUint32
	got, ok = parseUint32(float64(5000000000))
	if ok || got != 0 {
		t.Fatalf("parseUint32(>MaxUint32) = (%d, %v), want (0, false)", got, ok)
	}

	// Non-integer float
	got, ok = parseUint32(float64(1.5))
	if ok || got != 0 {
		t.Fatalf("parseUint32(1.5) = (%d, %v), want (0, false)", got, ok)
	}

	// Unknown type
	got, ok = parseUint32([]int{1})
	if ok || got != 0 {
		t.Fatalf("parseUint32(slice) = (%d, %v), want (0, false)", got, ok)
	}
}

func TestDefaultSourceForEventUnknown(t *testing.T) {
	// Non-LinuxEBPF provider
	got := defaultSourceForEvent("OtherProvider", 1)
	if got != "" {
		t.Fatalf("defaultSourceForEvent(OtherProvider, 1) = %q, want empty", got)
	}

	// Unknown event ID
	got = defaultSourceForEvent("LinuxEBPF", 99)
	if got != "" {
		t.Fatalf("defaultSourceForEvent(LinuxEBPF, 99) = %q, want empty", got)
	}
}
