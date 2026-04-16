package audit

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// auditLine represents one parsed line from an audit log.
type auditLine struct {
	RecordType string            // "SYSCALL", "CWD", "PATH", etc.
	AuditID    string            // raw "TIMESTAMP:SERIAL" string for grouping
	Timestamp  float64           // epoch seconds (e.g. 1775057805.797)
	Serial     uint64            // serial number within that second
	Fields     map[string]string // all key=value pairs
}

// parseLine parses a single audit log line into its components.
// Returns nil, nil for blank lines. Returns nil, error for malformed lines.
func parseLine(line string) (*auditLine, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	// Extract type=XXX
	if !strings.HasPrefix(line, "type=") {
		return nil, fmt.Errorf("line does not start with type=")
	}

	spaceIdx := strings.IndexByte(line, ' ')
	if spaceIdx < 0 {
		return nil, fmt.Errorf("no space after type field")
	}
	recordType := line[len("type="):spaceIdx]
	rest := line[spaceIdx+1:]

	// Extract msg=audit(TIMESTAMP:SERIAL):
	auditID, ts, serial, afterMsg, err := parseAuditID(rest)
	if err != nil {
		return nil, err
	}

	fields := parseKeyValuePairs(afterMsg)

	return &auditLine{
		RecordType: recordType,
		AuditID:    auditID,
		Timestamp:  ts,
		Serial:     serial,
		Fields:     fields,
	}, nil
}

// parseAuditID extracts timestamp and serial from "msg=audit(TIMESTAMP:SERIAL): rest".
// Returns the raw ID string, parsed timestamp, serial, and the remaining string.
func parseAuditID(s string) (string, float64, uint64, string, error) {
	const prefix = "msg=audit("
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return "", 0, 0, "", fmt.Errorf("missing msg=audit( header")
	}

	after := s[idx+len(prefix):]
	closeIdx := strings.IndexByte(after, ')')
	if closeIdx < 0 {
		return "", 0, 0, "", fmt.Errorf("missing closing parenthesis in audit ID")
	}

	idStr := after[:closeIdx] // "1775057805.797:696"
	colonIdx := strings.IndexByte(idStr, ':')
	if colonIdx < 0 {
		return "", 0, 0, "", fmt.Errorf("missing colon in audit ID %q", idStr)
	}

	ts, err := strconv.ParseFloat(idStr[:colonIdx], 64)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("parsing audit timestamp %q: %w", idStr[:colonIdx], err)
	}

	serial, err := strconv.ParseUint(idStr[colonIdx+1:], 10, 64)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("parsing audit serial %q: %w", idStr[colonIdx+1:], err)
	}

	// The rest starts after "):" and optional space
	rest := after[closeIdx+1:]
	rest = strings.TrimLeft(rest, ": ")

	return idStr, ts, serial, rest, nil
}

// parseKeyValuePairs parses the key=value portion of an audit line.
// Handles bare values, double-quoted values, single-quoted nested blocks
// (e.g. msg='op=PAM:authentication ... res=failed'), and hex-encoded values.
func parseKeyValuePairs(raw string) map[string]string {
	fields := make(map[string]string)
	raw = strings.TrimSpace(raw)

	for len(raw) > 0 {
		// Find key=
		eqIdx := strings.IndexByte(raw, '=')
		if eqIdx < 0 {
			break
		}

		key := raw[:eqIdx]
		raw = raw[eqIdx+1:]

		var value string
		if len(raw) > 0 && raw[0] == '\'' {
			// Single-quoted block (e.g. msg='op=PAM:authentication ... res=failed').
			// Contains nested key=value pairs. Extract the block, parse the
			// inner pairs as additional fields, and skip the outer key.
			endQuote := strings.IndexByte(raw[1:], '\'')
			if endQuote < 0 {
				value = raw[1:]
				raw = ""
			} else {
				inner := raw[1 : endQuote+1]
				raw = raw[endQuote+2:]
				for k, v := range parseKeyValuePairs(inner) {
					fields[k] = v
				}
				continue
			}
		} else if len(raw) > 0 && raw[0] == '"' {
			// Quoted value: read until closing quote
			endQuote := strings.IndexByte(raw[1:], '"')
			if endQuote < 0 {
				// No closing quote, take the rest
				value = raw[1:]
				raw = ""
			} else {
				value = raw[1 : endQuote+1]
				raw = raw[endQuote+2:]
			}
		} else {
			// Unquoted value: read until next space
			spaceIdx := strings.IndexByte(raw, ' ')
			if spaceIdx < 0 {
				value = raw
				raw = ""
			} else {
				value = raw[:spaceIdx]
				raw = raw[spaceIdx+1:]
			}
		}

		raw = strings.TrimLeft(raw, " ")
		fields[key] = value
	}

	return fields
}

// decodeHexField decodes a hex-encoded audit field value if it looks like hex.
// Returns the decoded string, or the original if it's not valid hex.
func decodeHexField(s string) string {
	if len(s) == 0 || len(s)%2 != 0 {
		return s
	}
	for _, c := range s {
		if !isHexDigit(c) {
			return s
		}
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return s
	}
	// Replace NUL bytes with spaces (common in proctitle)
	for i, b := range decoded {
		if b == 0 {
			decoded[i] = ' '
		}
	}
	return strings.TrimRight(string(decoded), " ")
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

