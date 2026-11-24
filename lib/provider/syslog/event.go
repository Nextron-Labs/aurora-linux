package syslog

import (
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

const (
	ProviderName = "LinuxSyslog"
	// SourceSyslog is the single source of all syslog/journal events.
	SourceSyslog = "LinuxSyslog:Syslog"
	// EventIDSyslog identifies syslog lines.
	EventIDSyslog uint16 = 300
)

type syslogEvent struct {
	pid      uint32
	ts       time.Time
	fields   enrichment.DataFieldsMap
	services []string
}

func (e *syslogEvent) ID() provider.EventIdentifier {
	return provider.EventIdentifier{ProviderName: ProviderName, EventID: EventIDSyslog}
}
func (e *syslogEvent) Process() uint32                             { return e.pid }
func (e *syslogEvent) Source() string                              { return SourceSyslog }
func (e *syslogEvent) Time() time.Time                             { return e.ts }
func (e *syslogEvent) Value(fieldname string) enrichment.DataValue { return e.fields.Value(fieldname) }
func (e *syslogEvent) ForEach(fn func(key, value string))          { e.fields.ForEach(fn) }
func (e *syslogEvent) Fields() enrichment.DataFieldsMap            { return e.fields }

// Services implements the Sigma consumer's logsource routing.
func (e *syslogEvent) Services() []string { return e.services }

// KeywordValues limits Sigma keyword matching to the message itself: the
// header (hostname, raw line, log path) must not satisfy keyword rules.
func (e *syslogEvent) KeywordValues() []string { return []string{e.fields.Value("message").String} }

// Fields emitted on every event.
var KnownFields = map[string]bool{
	"message": true, "program": true, "pid": true, "hostname": true,
	"facility": true, "severity": true, "raw": true, "log_source": true,
	"EventID": true,
}
