package ebpf

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Hand-written decoders for the hot ring-buffer records. binary.Read walks
// byte arrays element by element through reflection (thousands of operations
// per exec event), which is far too slow for syscall-rate events.

var le = binary.LittleEndian

// execExePathBytes is MAX_EXE_PATH of exec_monitor.c.
const execExePathBytes = 512

// registryRefreshInterval re-expands the inode watches (new users, package
// updates, files created while a refresh was pending).
const registryRefreshInterval = 60 * time.Second

const (
	auditEventSize = 8 + 8*4 + 6*4 + 4*8 + 16 + 256 + 256 + 8 // see struct audit_event
	// exec_event header; args (args_len bytes, at most auditArgsMax) follow.
	execEventSize   = 8 + 4*4 + 16 + 256 + 4 + 3*4 + 8 + 8
	tamperEventSize = 8 + 6*4 + 16
)

func decodeAuditEvent(b []byte, e *bpfAuditEvent) error {
	if len(b) < auditEventSize {
		return fmt.Errorf("audit event too short: %d < %d", len(b), auditEventSize)
	}
	e.TimestampNs = le.Uint64(b[0:])
	e.Op = le.Uint32(b[8:])
	e.Nr = le.Uint32(b[12:])
	e.Pid = le.Uint32(b[16:])
	e.Ppid = le.Uint32(b[20:])
	e.Uid = le.Uint32(b[24:])
	e.Gid = le.Uint32(b[28:])
	e.Euid = le.Uint32(b[32:])
	e.Egid = le.Uint32(b[36:])
	e.Dfd = int32(le.Uint32(b[40:]))
	e.Dfd2 = int32(le.Uint32(b[44:]))
	e.Flags = le.Uint32(b[48:])
	e.PathLen = le.Uint32(b[52:])
	e.Path2Len = le.Uint32(b[56:])
	e.Pad = le.Uint32(b[60:])
	for i := range e.Args {
		e.Args[i] = le.Uint64(b[64+8*i:])
	}
	copy(e.Comm[:], b[96:112])
	copy(e.Path[:], b[112:368])
	copy(e.Path2[:], b[368:624])
	e.StartNs = le.Uint64(b[624:])
	return nil
}

func decodeExecEvent(b []byte, e *bpfExecEvent) error {
	if len(b) < execEventSize {
		return fmt.Errorf("exec event too short: %d < %d", len(b), execEventSize)
	}
	e.TimestampNs = le.Uint64(b[0:])
	e.Pid = le.Uint32(b[8:])
	e.Ppid = le.Uint32(b[12:])
	e.Uid = le.Uint32(b[16:])
	e.Gid = le.Uint32(b[20:])
	copy(e.Comm[:], b[24:40])
	copy(e.Filename[:], b[40:296])
	e.FilenameLen = le.Uint32(b[296:])
	e.Euid = le.Uint32(b[300:])
	e.Egid = le.Uint32(b[304:])
	e.ArgsLen = le.Uint32(b[308:])
	e.StartNs = le.Uint64(b[312:])
	e.ExecID = le.Uint64(b[320:])
	// The record carries only the used part of args (variable length).
	args := b[execEventSize:]
	n := min(int(e.ArgsLen), len(args), auditArgsMax)
	e.ArgsLen = uint32(n)
	copy(e.Args[:], args[:n])
	clear(e.Args[n:])
	return nil
}

func decodeTamperEvent(b []byte, e *bpfTamperEvent) error {
	if len(b) < tamperEventSize {
		return fmt.Errorf("tamper event too short: %d < %d", len(b), tamperEventSize)
	}
	e.TimestampNs = le.Uint64(b[0:])
	e.Kind = le.Uint32(b[8:])
	e.Pid = le.Uint32(b[12:])
	e.Uid = le.Uint32(b[16:])
	e.Target = le.Uint32(b[20:])
	e.Arg = le.Uint32(b[24:])
	e.Arg2 = le.Uint32(b[28:])
	copy(e.Comm[:], b[32:48])
	if len(b) >= tamperEventSize+tamperPathBytes { // security-hook variant carries a path
		copy(e.Path[:], b[48:48+tamperPathBytes])
	}
	return nil
}

// struct file_event: ts, pid, uid, dfd, flags, filename[256], filename_len
const (
	fileEventSize = 8 + 4*4 + 256 + 4
	// struct net_event: ts, pid, uid, sport, dport, saddr[16], daddr[16], family, initiated, pad
	netEventSize = 8 + 4 + 4 + 2 + 2 + 16 + 16 + 1 + 1 + 2
	// struct bpf_event: ts, pid, uid, cmd, prog_type, ret(s64), prog_name[16]
	bpfEventSize = 8 + 4*4 + 8 + 16
)

func decodeFileEvent(b []byte, e *bpfFileEvent) error {
	if len(b) < fileEventSize {
		return fmt.Errorf("file event too short: %d < %d", len(b), fileEventSize)
	}
	e.TimestampNs = le.Uint64(b[0:])
	e.Pid = le.Uint32(b[8:])
	e.Uid = le.Uint32(b[12:])
	e.Dfd = int32(le.Uint32(b[16:]))
	e.Flags = le.Uint32(b[20:])
	copy(e.Filename[:], b[24:280])
	e.FilenameLen = le.Uint32(b[280:])
	return nil
}

func decodeNetEvent(b []byte, e *bpfNetEvent) error {
	if len(b) < netEventSize {
		return fmt.Errorf("net event too short: %d < %d", len(b), netEventSize)
	}
	e.TimestampNs = le.Uint64(b[0:])
	e.Pid = le.Uint32(b[8:])
	e.Uid = le.Uint32(b[12:])
	e.Sport = le.Uint16(b[16:])
	e.Dport = le.Uint16(b[18:])
	copy(e.Saddr[:], b[20:36])
	copy(e.Daddr[:], b[36:52])
	e.Family = b[52]
	e.Initiated = b[53]
	e.Pad = le.Uint16(b[54:])
	return nil
}

func decodeBpfEvent(b []byte, e *bpfBpfEvent) error {
	if len(b) < bpfEventSize {
		return fmt.Errorf("bpf event too short: %d < %d", len(b), bpfEventSize)
	}
	e.TimestampNs = le.Uint64(b[0:])
	e.Pid = le.Uint32(b[8:])
	e.Uid = le.Uint32(b[12:])
	e.Cmd = le.Uint32(b[16:])
	e.ProgType = le.Uint32(b[20:])
	e.RetVal = int64(le.Uint64(b[24:]))
	copy(e.ProgName[:], b[32:48])
	return nil
}
