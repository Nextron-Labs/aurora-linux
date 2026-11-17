package audit

import (
	"math"
	"time"
)

// maxPendingRecords bounds memory while records wait to complete. It also keeps
// batch reads moving: a whole file is read faster than any record can go idle,
// so reaching this limit is what emits the oldest records.
const maxPendingRecords = 1024

// auditRecord is a group of related audit lines forming one logical event.
type auditRecord struct {
	Key       string
	Timestamp time.Time
	Lines     []*auditLine
}

// pendingRecord is a record that may still receive lines.
type pendingRecord struct {
	key      string
	lines    []*auditLine
	lastSeen time.Time
}

// recordGrouper assembles audit lines into records by audit ID.
//
// A record's lines are written one at a time and can be interleaved with lines
// from events on other CPUs, so neither reaching EOF nor seeing a different ID
// means a record is finished. A record is complete once it has received no new
// lines for a while (see Expire), or when maxPendingRecords forces out the
// oldest one.
type recordGrouper struct {
	pending map[string]*pendingRecord
	order   []*pendingRecord // oldest first
}

func newRecordGrouper() *recordGrouper {
	return &recordGrouper{pending: make(map[string]*pendingRecord)}
}

// AddLine adds a parsed line to its record. It returns the oldest pending record
// if the new line pushed the grouper past maxPendingRecords, and nil otherwise.
func (g *recordGrouper) AddLine(line *auditLine, now time.Time) *auditRecord {
	rec, ok := g.pending[line.AuditID]
	if !ok {
		rec = &pendingRecord{key: line.AuditID}
		g.pending[line.AuditID] = rec
		g.order = append(g.order, rec)
	}
	rec.lines = append(rec.lines, line)
	rec.lastSeen = now

	if len(g.order) <= maxPendingRecords {
		return nil
	}
	oldest := g.order[0]
	g.order = g.order[1:]
	delete(g.pending, oldest.key)
	return oldest.build()
}

// Expire returns the records that have received no lines since cutoff, oldest
// first.
func (g *recordGrouper) Expire(cutoff time.Time) []*auditRecord {
	var expired []*auditRecord
	kept := g.order[:0]
	for _, rec := range g.order {
		if rec.lastSeen.After(cutoff) {
			kept = append(kept, rec)
			continue
		}
		delete(g.pending, rec.key)
		expired = append(expired, rec.build())
	}
	clear(g.order[len(kept):])
	g.order = kept
	return expired
}

// Flush returns all pending records, oldest first (called when reading stops).
func (g *recordGrouper) Flush() []*auditRecord {
	records := make([]*auditRecord, 0, len(g.order))
	for _, rec := range g.order {
		records = append(records, rec.build())
	}
	g.order = nil
	clear(g.pending)
	return records
}

func (p *pendingRecord) build() *auditRecord {
	return &auditRecord{
		Key:       p.key,
		Timestamp: auditTimestampToTime(p.lines[0].Timestamp),
		Lines:     p.lines,
	}
}

// auditTimestampToTime converts an audit epoch float to time.Time.
func auditTimestampToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64(math.Round((ts - float64(sec)) * 1e9))
	return time.Unix(sec, nsec)
}
