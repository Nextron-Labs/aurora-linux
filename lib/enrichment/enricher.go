package enrichment

import (
	"fmt"
	"sync"
)

// DataValue represents a single field value that may or may not be set.
type DataValue struct {
	Valid  bool
	String string
}

// DataFields provides access to key-value field data attached to events.
type DataFields interface {
	Value(fieldname string) DataValue
	ForEach(func(key string, value string))
}

// DataFieldsMap is a concrete implementation of DataFields backed by a map.
type DataFieldsMap map[string]fmt.Stringer

// stringValue wraps a plain string to implement fmt.Stringer.
type stringValue string

func (s stringValue) String() string {
	return string(s)
}

// NewStringValue creates a fmt.Stringer from a plain string.
func NewStringValue(s string) fmt.Stringer {
	return stringValue(s)
}

// Value returns the DataValue for a given field name.
func (m DataFieldsMap) Value(fieldname string) DataValue {
	v, ok := m[fieldname]
	if !ok || v == nil {
		return DataValue{}
	}
	return DataValue{Valid: true, String: v.String()}
}

// ForEach iterates over all fields in the map.
func (m DataFieldsMap) ForEach(fn func(key string, value string)) {
	for k, v := range m {
		if v != nil {
			fn(k, v.String())
		}
	}
}

// AddField adds a field to the map.
func (m DataFieldsMap) AddField(key string, value string) {
	m[key] = NewStringValue(value)
}

// RenameField renames a field key. Returns true if the old key existed.
func (m DataFieldsMap) RenameField(oldKey, newKey string) bool {
	v, ok := m[oldKey]
	if !ok {
		return false
	}
	m[newKey] = v
	delete(m, oldKey)
	return true
}

// EventEnricher applies enrichment functions to events based on their identity.
type EventEnricher struct {
	mu           sync.RWMutex
	manipulators map[string][]ManipulatorFunc
}

// ManipulatorFunc modifies a DataFieldsMap in place.
type ManipulatorFunc func(fields DataFieldsMap)

// NewEventEnricher creates a new enricher.
func NewEventEnricher() *EventEnricher {
	return &EventEnricher{
		manipulators: make(map[string][]ManipulatorFunc),
	}
}

// Register adds a manipulator function for a given provider+eventID key.
func (e *EventEnricher) Register(key string, fn ManipulatorFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.manipulators[key] = append(e.manipulators[key], fn)
}

// Enrich applies all registered manipulators for the given key to the fields.
func (e *EventEnricher) Enrich(key string, fields DataFieldsMap) {
	e.mu.RLock()
	manipulators := append([]ManipulatorFunc(nil), e.manipulators[key]...)
	e.mu.RUnlock()

	for _, fn := range manipulators {
		fn(fields)
	}
}
