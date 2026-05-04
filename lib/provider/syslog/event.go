package syslog

import (
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// ProviderName identifies events emitted by the syslog provider.
const ProviderName = "LinuxSyslog"

// SourceSyslog is the canonical source string for tailed syslog files.
const SourceSyslog = "LinuxSyslog:Syslog"

// EventIDSyslog is the (single) numeric event id for syslog-derived events.
// Sigma rules that target service: syslog match on keywords / parsed fields,
// not on a numeric EventID, so we re-use a constant.
const EventIDSyslog uint16 = 0

// syslogEvent implements provider.Event for parsed syslog lines.
type syslogEvent struct {
	id     provider.EventIdentifier
	pid    uint32
	source string
	ts     time.Time
	fields enrichment.DataFieldsMap
}

func (e *syslogEvent) ID() provider.EventIdentifier                { return e.id }
func (e *syslogEvent) Process() uint32                             { return e.pid }
func (e *syslogEvent) Source() string                              { return e.source }
func (e *syslogEvent) Time() time.Time                             { return e.ts }
func (e *syslogEvent) Value(fieldname string) enrichment.DataValue { return e.fields.Value(fieldname) }
func (e *syslogEvent) ForEach(fn func(key, value string))          { e.fields.ForEach(fn) }
func (e *syslogEvent) Fields() enrichment.DataFieldsMap            { return e.fields }
