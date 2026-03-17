package ebpf

import (
	"testing"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

func TestEbpfEventID(t *testing.T) {
	event := &ebpfEvent{
		id: provider.EventIdentifier{
			ProviderName: "LinuxEBPF",
			EventID:      1,
		},
	}

	got := event.ID()
	if got.ProviderName != "LinuxEBPF" {
		t.Fatalf("ID().ProviderName = %q, want LinuxEBPF", got.ProviderName)
	}
	if got.EventID != 1 {
		t.Fatalf("ID().EventID = %d, want 1", got.EventID)
	}
}

func TestEbpfEventProcess(t *testing.T) {
	event := &ebpfEvent{pid: 12345}

	if got := event.Process(); got != 12345 {
		t.Fatalf("Process() = %d, want 12345", got)
	}
}

func TestEbpfEventSource(t *testing.T) {
	event := &ebpfEvent{source: "LinuxEBPF:ProcessExec"}

	if got := event.Source(); got != "LinuxEBPF:ProcessExec" {
		t.Fatalf("Source() = %q, want LinuxEBPF:ProcessExec", got)
	}
}

func TestEbpfEventTime(t *testing.T) {
	ts := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	event := &ebpfEvent{ts: ts}

	if got := event.Time(); !got.Equal(ts) {
		t.Fatalf("Time() = %v, want %v", got, ts)
	}
}

func TestEbpfEventValue(t *testing.T) {
	event := &ebpfEvent{
		fields: enrichment.DataFieldsMap{
			"Image":       enrichment.NewStringValue("/usr/bin/bash"),
			"CommandLine": enrichment.NewStringValue("bash -c echo test"),
		},
	}

	// Test existing field
	got := event.Value("Image")
	if !got.Valid {
		t.Fatal("Value(Image).Valid = false, want true")
	}
	if got.String != "/usr/bin/bash" {
		t.Fatalf("Value(Image).String = %q, want /usr/bin/bash", got.String)
	}

	// Test non-existing field
	got = event.Value("NonExistent")
	if got.Valid {
		t.Fatal("Value(NonExistent).Valid = true, want false")
	}
}

func TestEbpfEventForEach(t *testing.T) {
	event := &ebpfEvent{
		fields: enrichment.DataFieldsMap{
			"Image":     enrichment.NewStringValue("/bin/bash"),
			"ProcessId": enrichment.NewStringValue("1234"),
		},
	}

	collected := make(map[string]string)
	event.ForEach(func(key, value string) {
		collected[key] = value
	})

	if len(collected) != 2 {
		t.Fatalf("ForEach collected %d fields, want 2", len(collected))
	}
	if collected["Image"] != "/bin/bash" {
		t.Fatalf("collected[Image] = %q, want /bin/bash", collected["Image"])
	}
	if collected["ProcessId"] != "1234" {
		t.Fatalf("collected[ProcessId] = %q, want 1234", collected["ProcessId"])
	}
}

func TestEbpfEventFields(t *testing.T) {
	fields := enrichment.DataFieldsMap{
		"Image": enrichment.NewStringValue("/bin/bash"),
	}
	event := &ebpfEvent{fields: fields}

	got := event.Fields()
	if got["Image"].String() != "/bin/bash" {
		t.Fatalf("Fields()[Image] = %q, want /bin/bash", got["Image"].String())
	}

	// Verify it returns the underlying map (not a copy)
	got.AddField("NewField", "new value")
	if event.fields["NewField"] == nil {
		t.Fatal("Fields() should return the underlying map, not a copy")
	}
}

func TestEventConstants(t *testing.T) {
	if ProviderName != "LinuxEBPF" {
		t.Fatalf("ProviderName = %q, want LinuxEBPF", ProviderName)
	}
	if EventIDProcessCreation != 1 {
		t.Fatalf("EventIDProcessCreation = %d, want 1", EventIDProcessCreation)
	}
	if EventIDNetworkConnection != 3 {
		t.Fatalf("EventIDNetworkConnection = %d, want 3", EventIDNetworkConnection)
	}
	if EventIDFileEvent != 11 {
		t.Fatalf("EventIDFileEvent = %d, want 11", EventIDFileEvent)
	}
}

func TestEbpfEventEmptyFields(t *testing.T) {
	event := &ebpfEvent{
		fields: enrichment.DataFieldsMap{},
	}

	// ForEach with empty fields should not panic
	count := 0
	event.ForEach(func(key, value string) {
		count++
	})
	if count != 0 {
		t.Fatalf("ForEach iterated %d times, want 0", count)
	}
}

func TestEbpfEventNilFieldsMap(t *testing.T) {
	event := &ebpfEvent{
		fields: nil,
	}

	// Value with nil fields should return invalid value
	got := event.Value("Image")
	if got.Valid {
		t.Fatal("Value on nil fields should return Valid=false")
	}
}
