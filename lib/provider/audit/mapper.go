package audit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
	"github.com/Nextron-Labs/aurora-linux/lib/provider"
)

// mapRecordToEvents converts a grouped audit record into one or more events.
// Each audit record type (SYSCALL, EXECVE, PATH, PROCTITLE, etc.) in the group
// produces one event. SYSCALL fields are merged into every event as context,
// since sigma rules commonly reference fields like "key" or "exe" alongside
// other record types.
func mapRecordToEvents(record *auditRecord) []*auditEvent {
	// Find SYSCALL line (if any) — its fields are merged into all events.
	var syscallFields map[string]string
	var pid uint32
	for _, line := range record.Lines {
		if line.RecordType == "SYSCALL" {
			syscallFields = line.Fields
			if pidStr, ok := line.Fields["pid"]; ok {
				if n, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
					pid = uint32(n)
				}
			}
			break
		}
	}

	var events []*auditEvent
	for _, line := range record.Lines {
		fields := buildRawFieldsMap(line, syscallFields)

		// If no pid from SYSCALL, try from this line
		evtPid := pid
		if evtPid == 0 {
			if pidStr, ok := line.Fields["pid"]; ok {
				if n, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
					evtPid = uint32(n)
				}
			}
		}

		events = append(events, &auditEvent{
			id: provider.EventIdentifier{
				ProviderName: ProviderName,
				EventID:      EventIDAudit,
			},
			pid:    evtPid,
			source: SourceAuditd,
			ts:     record.Timestamp,
			fields: fields,
		})
	}

	return events
}

// buildRawFieldsMap creates a DataFieldsMap with raw audit fields.
// The "type" field is set to the record type (SYSCALL, EXECVE, PATH, etc.).
// If syscallFields is provided, those fields are merged in (without overwriting
// fields already present on this line).
func buildRawFieldsMap(line *auditLine, syscallFields map[string]string) enrichment.DataFieldsMap {
	// Estimate capacity: line fields + syscall fields + type field
	capacity := len(line.Fields) + 1
	if syscallFields != nil {
		capacity += len(syscallFields)
	}
	fields := make(enrichment.DataFieldsMap, capacity)

	// Set record type
	fields.AddField("type", line.RecordType)

	// Add all fields from the SYSCALL record as context (won't overwrite)
	if syscallFields != nil && line.RecordType != "SYSCALL" {
		for k, v := range syscallFields {
			fields.AddField(k, v)
		}
	}

	// Add this record's own fields (overwrites SYSCALL fields if same key)
	for k, v := range line.Fields {
		// Decode hex-encoded fields (common in PROCTITLE, EXECVE)
		if shouldDecodeHex(line.RecordType, k) {
			v = decodeHexField(v)
		}
		fields.AddField(k, v)
	}

	return fields
}

// shouldDecodeHex returns true for fields that are commonly hex-encoded.
func shouldDecodeHex(recordType, key string) bool {
	switch recordType {
	case "PROCTITLE":
		return key == "proctitle"
	case "EXECVE":
		// EXECVE args (a0, a1, ...) can be hex-encoded
		return strings.HasPrefix(key, "a") && len(key) >= 2 && isDigit(key[1])
	}
	return false
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// reassembleExecveArgs joins EXECVE a0, a1, ... fields into a command line.
// Exported for use in enrichment if needed.
func reassembleExecveArgs(fields map[string]string) string {
	argc, _ := strconv.Atoi(fields["argc"])
	if argc == 0 {
		// Try to find args by scanning
		for i := 0; ; i++ {
			if _, ok := fields[fmt.Sprintf("a%d", i)]; !ok {
				argc = i
				break
			}
		}
	}

	args := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		key := fmt.Sprintf("a%d", i)
		if val, ok := fields[key]; ok {
			args = append(args, decodeHexField(val))
		}
	}
	return strings.Join(args, " ")
}
