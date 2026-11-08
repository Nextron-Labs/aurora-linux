package provider

import (
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
)

// EventIdentifier uniquely identifies an event type from a provider.
type EventIdentifier struct {
	ProviderName string
	EventID      uint16
}

// Event represents a normalized telemetry event flowing through the pipeline.
type Event interface {
	ID() EventIdentifier
	Process() uint32
	Source() string
	Time() time.Time
	enrichment.DataFields
}

// EventProvider is the interface all telemetry providers must implement.
type EventProvider interface {
	Name() string
	Description() string
	Initialize() error
	Close() error
	AddSource(source string) error
	SendEvents(callback func(event Event))
	LostEvents() uint64
}
