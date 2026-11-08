package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
	log "github.com/sirupsen/logrus"
)

// ReplayProvider implements EventProvider by reading recorded events from a
// JSONL file. Used in CI and testing environments where BPF is unavailable.
type ReplayProvider struct {
	files     []string
	sources   map[string]bool
	sourcesMu sync.RWMutex
	closed    atomic.Bool
}

const maxReplayLineBytes = 4 * 1024 * 1024

// New creates a new ReplayProvider for the given JSONL files.
func New(files ...string) *ReplayProvider {
	return &ReplayProvider{
		files:   files,
		sources: make(map[string]bool),
	}
}

func (r *ReplayProvider) Name() string        { return "Replay" }
func (r *ReplayProvider) Description() string { return "Replay provider for pre-recorded events" }
func (r *ReplayProvider) LostEvents() uint64  { return 0 }
func (r *ReplayProvider) Close() error {
	r.closed.Store(true)
	return nil
}
func (r *ReplayProvider) Initialize() error {
	r.closed.Store(false)
	return nil
}

func (r *ReplayProvider) AddSource(source string) error {
	r.sourcesMu.Lock()
	defer r.sourcesMu.Unlock()
	r.sources[source] = true
	return nil
}

// SendEvents reads each JSONL file and emits events via the callback.
func (r *ReplayProvider) SendEvents(callback func(event provider.Event)) {
	for _, path := range r.files {
		if r.closed.Load() {
			return
		}
		r.replayFile(path, callback)
	}
}

func (r *ReplayProvider) replayFile(path string, callback func(event provider.Event)) {
	f, err := os.Open(path)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": "Replay",
			"path":     path,
		}).WithError(err).Warn("Failed to open replay input file")
		return
	}
	defer f.Close()

	lineNo := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxReplayLineBytes)

	for scanner.Scan() {
		if r.closed.Load() {
			return
		}

		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var record map[string]interface{}
		if err := json.Unmarshal(line, &record); err != nil {
			log.WithFields(log.Fields{
				"provider": "Replay",
				"path":     path,
				"line":     lineNo,
			}).WithError(err).Debug("Skipping invalid replay JSON line")
			continue
		}

		evt, err := recordToEvent(record)
		if err != nil {
			log.WithFields(log.Fields{
				"provider": "Replay",
				"path":     path,
				"line":     lineNo,
			}).WithError(err).Debug("Skipping replay record that failed normalization")
			continue
		}
		if !r.sourceEnabled(evt.Source()) {
			continue
		}

		callback(evt)
	}

	if err := scanner.Err(); err != nil {
		log.WithFields(log.Fields{
			"provider": "Replay",
			"path":     path,
		}).WithError(err).Warnf("Failed while reading replay input file (max line size %d bytes)", maxReplayLineBytes)
	}
}

func (r *ReplayProvider) sourceEnabled(source string) bool {
	r.sourcesMu.RLock()
	defer r.sourcesMu.RUnlock()
	if len(r.sources) == 0 {
		return true
	}
	return r.sources[source]
}

func recordToEvent(record map[string]interface{}) (*replayEvent, error) {
	fields := make(enrichment.DataFieldsMap, len(record))

	var providerName string
	var eventID uint16
	var source string
	var pid uint32
	var ts time.Time

	for k, v := range record {
		switch k {
		case "_provider":
			providerName, _ = v.(string)
		case "_eventID":
			eventID = parseEventID(v)
		case "_source":
			source, _ = v.(string)
		case "_timestamp":
			if s, ok := v.(string); ok {
				ts, _ = time.Parse(time.RFC3339Nano, s)
			}
		case "ProcessId":
			if n, ok := parseUint32(v); ok {
				pid = n
			}
			fields.AddField(k, fmt.Sprint(v))
		default:
			fields.AddField(k, fmt.Sprint(v))
		}
	}

	if providerName == "" {
		providerName = "LinuxEBPF"
	}
	if source == "" {
		source = defaultSourceForEvent(providerName, eventID)
	}
	if ts.IsZero() {
		ts = time.Now()
	}

	return &replayEvent{
		id: provider.EventIdentifier{
			ProviderName: providerName,
			EventID:      eventID,
		},
		pid:    pid,
		source: source,
		ts:     ts,
		fields: fields,
	}, nil
}

func parseEventID(v interface{}) uint16 {
	switch x := v.(type) {
	case float64:
		if x >= 0 && x <= math.MaxUint16 && math.Trunc(x) == x {
			return uint16(x)
		}
	case string:
		if n, err := strconv.ParseUint(x, 10, 16); err == nil {
			return uint16(n)
		}
	}
	return 0
}

func parseUint32(v interface{}) (uint32, bool) {
	switch x := v.(type) {
	case string:
		n, err := strconv.ParseUint(x, 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(n), true
	case float64:
		if x < 0 || x > math.MaxUint32 || math.Trunc(x) != x {
			return 0, false
		}
		return uint32(x), true
	}
	return 0, false
}

func defaultSourceForEvent(providerName string, eventID uint16) string {
	if providerName != "LinuxEBPF" {
		return ""
	}
	switch eventID {
	case 1:
		return "LinuxEBPF:ProcessExec"
	case 3:
		return "LinuxEBPF:NetConnect"
	case 11:
		return "LinuxEBPF:FileCreate"
	case 100:
		return "LinuxEBPF:BpfEvent"
	default:
		return ""
	}
}

// replayEvent implements provider.Event for replayed events.
type replayEvent struct {
	id     provider.EventIdentifier
	pid    uint32
	source string
	ts     time.Time
	fields enrichment.DataFieldsMap
}

func (e *replayEvent) ID() provider.EventIdentifier                { return e.id }
func (e *replayEvent) Process() uint32                             { return e.pid }
func (e *replayEvent) Source() string                              { return e.source }
func (e *replayEvent) Time() time.Time                             { return e.ts }
func (e *replayEvent) Value(fieldname string) enrichment.DataValue { return e.fields.Value(fieldname) }
func (e *replayEvent) ForEach(fn func(key, value string))          { e.fields.ForEach(fn) }
func (e *replayEvent) Fields() enrichment.DataFieldsMap            { return e.fields }
