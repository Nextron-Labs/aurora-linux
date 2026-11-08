package audit

import (
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

const ProviderName = "LinuxAudit"

// Single source string — all audit events go through the same source.
const SourceAuditd = "LinuxAudit:Auditd"

// EventIDAudit is used for all audit events. Sigma rules match on raw
// audit fields (type, syscall, key, exe, a0, ...) not on Sysmon EventIDs.
const EventIDAudit uint16 = 0

// auditEvent implements provider.Event for audit-sourced events.
type auditEvent struct {
	id     provider.EventIdentifier
	pid    uint32
	source string
	ts     time.Time
	fields enrichment.DataFieldsMap
}

func (e *auditEvent) ID() provider.EventIdentifier                { return e.id }
func (e *auditEvent) Process() uint32                             { return e.pid }
func (e *auditEvent) Source() string                              { return e.source }
func (e *auditEvent) Time() time.Time                             { return e.ts }
func (e *auditEvent) Value(fieldname string) enrichment.DataValue { return e.fields.Value(fieldname) }
func (e *auditEvent) ForEach(fn func(key, value string))          { e.fields.ForEach(fn) }
func (e *auditEvent) Fields() enrichment.DataFieldsMap            { return e.fields }
