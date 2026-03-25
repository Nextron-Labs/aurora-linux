package ebpf

import (
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

const (
	ProviderName = "LinuxEBPF"

	// Event IDs aligned with Sysmon for familiarity.
	EventIDProcessCreation   uint16 = 1
	EventIDNetworkConnection uint16 = 3
	EventIDFileEvent         uint16 = 11
	EventIDBpfEvent          uint16 = 100
)

// ebpfEvent is the concrete Event implementation for events from the eBPF provider.
type ebpfEvent struct {
	id     provider.EventIdentifier
	pid    uint32
	source string
	ts     time.Time
	fields enrichment.DataFieldsMap
}

// ID returns the event identifier.
func (e *ebpfEvent) ID() provider.EventIdentifier {
	return e.id
}

// Process returns the PID of the process that generated the event.
func (e *ebpfEvent) Process() uint32 {
	return e.pid
}

// Source returns the provider source string (e.g., "LinuxEBPF:ProcessExec").
func (e *ebpfEvent) Source() string {
	return e.source
}

// Time returns the event timestamp.
func (e *ebpfEvent) Time() time.Time {
	return e.ts
}

// Value returns a field value by name.
func (e *ebpfEvent) Value(fieldname string) enrichment.DataValue {
	return e.fields.Value(fieldname)
}

// ForEach iterates over all fields.
func (e *ebpfEvent) ForEach(fn func(key string, value string)) {
	e.fields.ForEach(fn)
}

// Fields returns the underlying DataFieldsMap for direct manipulation by enrichers.
func (e *ebpfEvent) Fields() enrichment.DataFieldsMap {
	return e.fields
}
