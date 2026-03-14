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
