package ebpf

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

// procIdentity is what Aurora learned about a process while it was alive.
type procIdentity struct {
	startNs uint64
	execID  uint64 // leader's self_exec_id; 0 = unknown (tracepoint fallback)
	exe     string
	auid    string
}

// identityCache remembers exe/auid per pid, validated by the process start
// time, so that events from processes that already exited (or whose pid was
// reused) are attributed correctly instead of through a racy /proc lookup.
type identityCache struct {
	c *lru.Cache[uint32, procIdentity]
}

func newIdentityCache(size int) *identityCache {
	c, err := lru.New[uint32, procIdentity](size)
	if err != nil {
		return &identityCache{}
	}
	return &identityCache{c: c}
}

func (ic *identityCache) put(pid uint32, id procIdentity) {
	if ic != nil && ic.c != nil && id.startNs != 0 {
		ic.c.Add(pid, id)
	}
}

// resolve returns exe and auid of the process (pid, startNs, execID). A
// cached identity is only used if the start time matches and, when both are
// known, the exec generation too (a re-exec keeps pid and start time).
// Order:
//  1. the cache (exact, survives process exit);
//  2. /proc, accepted only if its start time matches (no pid reuse), and then
//     cached;
//
// otherwise exe is empty and auid is the audit "unset" value.
func (ic *identityCache) resolve(pid uint32, startNs, execID uint64) (exe, auid string) {
	if ic != nil && ic.c != nil && startNs != 0 {
		if id, ok := ic.c.Get(pid); ok && id.startNs == startNs &&
			(execID == 0 || id.execID == 0 || id.execID == execID) {
			return id.exe, id.auid
		}
	}
	if startNs != 0 {
		ticks, ok := readStartTicks(pid)
		if !ok || !startMatches(ticks, startNs) {
			return "", auditUnsetID
		}
	}
	exe, _ = readExeLink(pid)
	auid = auditLoginUID(pid)
	ic.put(pid, procIdentity{startNs: startNs, execID: execID, exe: exe, auid: auid})
	return exe, auid
}
