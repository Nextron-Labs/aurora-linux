package ebpf

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/Nextron-Labs/aurora-linux/lib/enrichment"
)

// joinCmdline converts NUL-separated /proc/PID/cmdline bytes into a
// space-separated command line string. If the data fills the entire buffer
// (maxCmdlineBytes), a truncation suffix is appended.
func joinCmdline(data []byte) (cmdline string, truncated bool) {
	if len(data) == 0 {
		return "", false
	}

	// Replace NUL bytes with spaces
	s := strings.ReplaceAll(string(data), "\x00", " ")
	s = strings.TrimRight(s, " ")

	truncated = len(data) >= maxCmdlineBytes
	if truncated {
		s += " ...(truncated)"
	}
	return s, truncated
}

// buildExecFieldsMap constructs the DataFieldsMap for a process_creation event.
func buildExecFieldsMap(
	pid, ppid, uid uint32,
	bpfFilename string,
	image string,
	cmdline string,
	truncated bool,
	cwd string,
	loginUID string,
	username string,
	parentImage string,
	parentCmdline string,
) enrichment.DataFieldsMap {
	fields := make(enrichment.DataFieldsMap, 12)

	fields.AddField("Image", image)
	fields.AddField("CommandLine", cmdline)
	fields.AddField("ParentImage", parentImage)
	fields.AddField("ParentCommandLine", parentCmdline)
	fields.AddField("User", username)
	fields.AddField("LogonId", loginUID)
	fields.AddField("CurrentDirectory", cwd)
	fields.AddField("ProcessId", strconv.FormatUint(uint64(pid), 10))
	fields.AddField("ParentProcessId", strconv.FormatUint(uint64(ppid), 10))

	if truncated {
		fields.AddField("CommandLineTruncated", "true")
	}

	return fields
}

// buildFileFieldsMap constructs the DataFieldsMap for a file_event.
func buildFileFieldsMap(
	pid, uid uint32,
	targetFilename string,
	image string,
	username string,
	flags uint32,
) enrichment.DataFieldsMap {
	fields := make(enrichment.DataFieldsMap, 6)

	fields.AddField("TargetFilename", targetFilename)
	fields.AddField("Image", image)
	fields.AddField("User", username)
	fields.AddField("ProcessId", strconv.FormatUint(uint64(pid), 10))
	fields.AddField("FileFlags", strconv.FormatUint(uint64(flags), 10))

	return fields
}

// buildNetFieldsMap constructs the DataFieldsMap for a network_connection event.
func buildNetFieldsMap(
	pid, uid uint32,
	image string,
	username string,
	srcIP string,
	srcPort uint16,
	dstIP string,
	dstPort uint16,
	initiated bool,
) enrichment.DataFieldsMap {
	fields := make(enrichment.DataFieldsMap, 10)

	fields.AddField("Image", image)
	fields.AddField("DestinationIp", dstIP)
	fields.AddField("DestinationPort", strconv.Itoa(int(dstPort)))
	fields.AddField("SourceIp", srcIP)
	fields.AddField("SourcePort", strconv.Itoa(int(srcPort)))
	fields.AddField("User", username)
	fields.AddField("ProcessId", strconv.FormatUint(uint64(pid), 10))
	fields.AddField("Protocol", "tcp")
	fields.AddField("DestinationHostname", "") // Phase 2: DNS correlation

	if initiated {
		fields.AddField("Initiated", "true")
	} else {
		fields.AddField("Initiated", "false")
	}

	return fields
}

// BPF command names aligned with Sysmon output.
var bpfCmdNames = map[uint32]string{
	0:  "BPF_MAP_CREATE",
	1:  "BPF_MAP_LOOKUP_ELEM",
	2:  "BPF_MAP_UPDATE_ELEM",
	3:  "BPF_MAP_DELETE_ELEM",
	4:  "BPF_MAP_GET_NEXT_KEY",
	5:  "BPF_PROG_LOAD",
	6:  "BPF_OBJ_PIN",
	7:  "BPF_OBJ_GET",
	8:  "BPF_PROG_ATTACH",
	9:  "BPF_PROG_DETACH",
	10: "BPF_PROG_TEST_RUN",
	11: "BPF_PROG_GET_NEXT_ID",
	12: "BPF_MAP_GET_NEXT_ID",
	13: "BPF_PROG_GET_FD_BY_ID",
	14: "BPF_MAP_GET_FD_BY_ID",
	15: "BPF_OBJ_GET_INFO_BY_FD",
	16: "BPF_PROG_QUERY",
	17: "BPF_RAW_TRACEPOINT_OPEN",
	18: "BPF_BTF_LOAD",
	19: "BPF_BTF_GET_FD_BY_ID",
	20: "BPF_TASK_FD_QUERY",
	21: "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
	22: "BPF_MAP_FREEZE",
	23: "BPF_BTF_GET_NEXT_ID",
	24: "BPF_MAP_LOOKUP_BATCH",
	25: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
	26: "BPF_MAP_UPDATE_BATCH",
	27: "BPF_MAP_DELETE_BATCH",
	28: "BPF_LINK_CREATE",
	29: "BPF_LINK_UPDATE",
	30: "BPF_LINK_GET_FD_BY_ID",
	31: "BPF_LINK_GET_NEXT_ID",
	32: "BPF_ENABLE_STATS",
	33: "BPF_ITER_CREATE",
	34: "BPF_LINK_DETACH",
	35: "BPF_PROG_BIND_MAP",
}

// BPF program type names aligned with Sysmon output.
var bpfProgTypeNames = map[uint32]string{
	0:  "UNSPEC",
	1:  "SOCKET_FILTER",
	2:  "KPROBE",
	3:  "SCHED_CLS",
	4:  "SCHED_ACT",
	5:  "TRACEPOINT",
	6:  "XDP",
	7:  "PERF_EVENT",
	8:  "CGROUP_SKB",
	9:  "CGROUP_SOCK",
	10: "LWT_IN",
	11: "LWT_OUT",
	12: "LWT_XMIT",
	13: "SOCK_OPS",
	14: "SK_SKB",
	15: "CGROUP_DEVICE",
	16: "SK_MSG",
	17: "RAW_TRACEPOINT",
	18: "CGROUP_SOCK_ADDR",
	19: "LWT_SEG6LOCAL",
	20: "LIRC_MODE2",
	21: "SK_REUSEPORT",
	22: "FLOW_DISSECTOR",
	23: "CGROUP_SYSCTL",
	24: "RAW_TRACEPOINT_WRITABLE",
	25: "CGROUP_SOCKOPT",
	26: "TRACING",
	27: "STRUCT_OPS",
	28: "EXT",
	29: "LSM",
	30: "SK_LOOKUP",
	31: "SYSCALL",
}

func bpfCmdName(cmd uint32) string {
	if name, ok := bpfCmdNames[cmd]; ok {
		return name
	}
	return strconv.FormatUint(uint64(cmd), 10)
}

func bpfProgTypeName(pt uint32) string {
	if name, ok := bpfProgTypeNames[pt]; ok {
		return name
	}
	return strconv.FormatUint(uint64(pt), 10)
}

// buildBpfFieldsMap constructs the DataFieldsMap for a bpf_event.
func buildBpfFieldsMap(
	pid, uid uint32,
	image string,
	username string,
	cmd uint32,
	progType uint32,
	retVal int64,
	progName string,
) enrichment.DataFieldsMap {
	fields := make(enrichment.DataFieldsMap, 8)

	fields.AddField("Image", image)
	fields.AddField("User", username)
	fields.AddField("ProcessId", strconv.FormatUint(uint64(pid), 10))
	fields.AddField("BpfCommand", bpfCmdName(cmd))
	fields.AddField("BpfProgramType", bpfProgTypeName(progType))
	fields.AddField("BpfProgramId", strconv.FormatInt(retVal, 10))

	if progName == "" {
		fields.AddField("BpfProgramName", "-")
	} else {
		fields.AddField("BpfProgramName", progName)
	}

	return fields
}

// formatIPv4 formats a v4-mapped-v6 address (bytes 12-15) as dotted decimal.
func formatIPv4(addr [16]byte) string {
	return strconv.Itoa(int(addr[12])) + "." +
		strconv.Itoa(int(addr[13])) + "." +
		strconv.Itoa(int(addr[14])) + "." +
		strconv.Itoa(int(addr[15]))
}

// formatIPv6 formats a 16-byte IPv6 address as a string.
func formatIPv6(addr [16]byte) string {
	return netip.AddrFrom16(addr).String()
}
