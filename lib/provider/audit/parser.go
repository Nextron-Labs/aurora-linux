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

	// auditd.conf name_format prefixes every line with node=<name>.
	var node string
	if strings.HasPrefix(line, "node=") {
		spaceIdx := strings.IndexByte(line, ' ')
		if spaceIdx < 0 {
			return nil, fmt.Errorf("no space after node field")
		}
		node = line[len("node="):spaceIdx]
		line = strings.TrimLeft(line[spaceIdx+1:], " ")
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

	fields := parseKeyValuePairs(recordType, afterMsg)
	if node != "" {
		fields["node"] = node
	}

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

// fieldSeparators ends an unquoted value. log_format = ENRICHED adds resolved
// fields (ARCH, SYSCALL, UID, ...) after a 0x1d byte rather than a space.
const fieldSeparators = " \x1d"

// parseKeyValuePairs parses the key=value portion of an audit line.
// Handles bare values, double-quoted values, and hex-encoded values.
//
// The kernel logs an untrusted string in double quotes when it is safe to print
// and as bare hex otherwise, so only unquoted values are candidates for hex
// decoding. A quoted argument such as a0="dd" is literal text.
func parseKeyValuePairs(recordType, raw string) map[string]string {
	fields := make(map[string]string)
	raw = strings.TrimLeft(strings.TrimSpace(raw), fieldSeparators)

	for len(raw) > 0 {
		// Find key=
		eqIdx := strings.IndexByte(raw, '=')
		if eqIdx < 0 {
			break
		}

		key := raw[:eqIdx]
		raw = raw[eqIdx+1:]

		// Free text can precede a key, as in "avc:  denied  { read } for  pid=1".
		if sepIdx := strings.LastIndexAny(key, fieldSeparators); sepIdx >= 0 {
			key = key[sepIdx+1:]
		}

		// User-space records wrap their fields in msg='...'. Keep the text, which
		// may not be key=value at all, and parse its contents as ordinary fields.
		if key == "msg" && strings.HasPrefix(raw, "'") {
			message, rest := splitQuotedMessage(raw)
			fields[key] = message
			raw = message + " " + rest
			continue
		}

		var value string
		if len(raw) > 0 && raw[0] == '"' {
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
			// Unquoted value: read until the next separator
			sepIdx := strings.IndexAny(raw, fieldSeparators)
			if sepIdx < 0 {
				value = raw
				raw = ""
			} else {
				value = raw[:sepIdx]
				raw = raw[sepIdx+1:]
			}
			if shouldDecodeHex(recordType, key) {
				value = decodeHexField(value)
			}
		}

		raw = strings.TrimLeft(raw, fieldSeparators)
		fields[key] = value
	}

	return fields
}

// splitQuotedMessage splits a value starting with a single quote into the quoted
// text and whatever follows the closing quote. Values inside the text can contain
// apostrophes (acct="o'brien"), and so can ENRICHED fields after it, so the closing
// quote is the last one before the 0x1d separator. A line truncated before its
// closing quote yields the text up to the separator or the end of the line.
func splitQuotedMessage(raw string) (message, rest string) {
	raw = raw[1:]
	end := len(raw)
	if sepIdx := strings.IndexByte(raw, '\x1d'); sepIdx >= 0 {
		end = sepIdx
	}
	if quoteIdx := strings.LastIndexByte(raw[:end], '\''); quoteIdx >= 0 {
		return raw[:quoteIdx], raw[quoteIdx+1:]
	}
	return raw[:end], raw[end:]
}

// shouldDecodeHex returns true for fields whose unquoted values are hex-encoded.
// exe, comm, name and cwd hold untrusted strings in whichever record carries
// them, so a path containing a space arrives as hex. A non-hex placeholder such
// as name=(null) passes through decodeHexField unchanged.
func shouldDecodeHex(recordType, key string) bool {
	switch key {
	case "exe", "comm", "name", "cwd":
		return true
	}
	switch recordType {
	case "PROCTITLE":
		return key == "proctitle"
	case "EXECVE":
		return isExecveArgKey(key)
	}
	return false
}

// isExecveArgKey matches a<N> and a<N>[<M>] (long arguments split across
// lines). It excludes a<N>_len, which is a plain decimal length.
func isExecveArgKey(key string) bool {
	if len(key) < 2 || key[0] != 'a' {
		return false
	}
	index := key[1:]
	if bracket := strings.IndexByte(index, '['); bracket >= 0 {
		index = index[:bracket]
	}
	if index == "" {
		return false
	}
	for i := 0; i < len(index); i++ {
		if index[i] < '0' || index[i] > '9' {
			return false
		}
	}
	return true
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
