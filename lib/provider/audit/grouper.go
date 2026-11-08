package audit

import (
	"math"
	"time"
)

// auditRecord is a group of related audit lines forming one logical event.
type auditRecord struct {
	Key       string
	Timestamp time.Time
	Lines     []*auditLine
}

// recordGrouper accumulates audit lines and emits complete records.
// Audit records for the same event are always consecutive in the log,
// so we flush when the key changes.
type recordGrouper struct {
	currentKey    string
	currentLines  []*auditLine
	hasCurrentKey bool
}

func newRecordGrouper() *recordGrouper {
	return &recordGrouper{}
}

// AddLine adds a parsed line. Returns a completed record if the key changed,
// meaning the previous group is done.
func (g *recordGrouper) AddLine(line *auditLine) *auditRecord {
	key := line.AuditID

	if g.hasCurrentKey && key != g.currentKey {
		// Key changed — flush previous record
		completed := g.buildRecord()
		g.currentKey = key
		g.hasCurrentKey = true
		g.currentLines = []*auditLine{line}
		return completed
	}

	// Same key or first line
	g.currentKey = key
	g.hasCurrentKey = true
	g.currentLines = append(g.currentLines, line)
	return nil
}

// Flush returns the remaining pending record (called at EOF).
func (g *recordGrouper) Flush() *auditRecord {
	if !g.hasCurrentKey || len(g.currentLines) == 0 {
		return nil
	}
	return g.buildRecord()
}

func (g *recordGrouper) buildRecord() *auditRecord {
	var ts time.Time
	if len(g.currentLines) > 0 {
		ts = auditTimestampToTime(g.currentLines[0].Timestamp)
	}
	rec := &auditRecord{
		Key:       g.currentKey,
		Timestamp: ts,
		Lines:     g.currentLines,
	}
	g.currentLines = nil
	g.hasCurrentKey = false
	return rec
}

// auditTimestampToTime converts an audit epoch float to time.Time.
func auditTimestampToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64(math.Round((ts - float64(sec)) * 1e9))
	return time.Unix(sec, nsec)
}
