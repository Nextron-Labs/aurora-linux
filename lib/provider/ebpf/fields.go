package ebpf

import "regexp"

// Field catalog: every event field Aurora's eBPF provider can emit. It lets the
// Sigma consumer detect rules that can never match.

var sysmonStyleFields = map[string]bool{
	"EventID": true,
	// process_creation
	"Image": true, "CommandLine": true, "ParentImage": true, "ParentCommandLine": true,
	"User": true, "LogonId": true, "CurrentDirectory": true, "ProcessId": true,
	"ParentProcessId": true, "CommandLineTruncated": true,
	// file_event
	"TargetFilename": true, "FileFlags": true,
	// network_connection
	"DestinationIp": true, "DestinationPort": true, "SourceIp": true, "SourcePort": true,
	"Protocol": true, "DestinationHostname": true, "Initiated": true,
	// bpf_event
	"BpfCommand": true, "BpfProgramType": true, "BpfProgramId": true, "BpfProgramName": true,
}

var auditStyleFields = map[string]bool{
	"EventID": true,
	"type":    true, "arch": true, "syscall": true, "SYSCALL": true, "success": true,
	"pid": true, "ppid": true, "auid": true, "uid": true, "gid": true, "euid": true, "egid": true,
	"comm": true, "exe": true, "key": true, "argc": true, "proctitle": true,
	"item": true, "name": true, "nametype": true,
	"unit": true, "res": true, "acct": true,
	"daddr": true, "dport": true, "saddr": true,
}

var auditArgField = regexp.MustCompile(`^a[0-9]+$`)

// IsSysmonStyleField reports whether the provider emits field in
// process/file/network/bpf events.
func IsSysmonStyleField(field string) bool { return sysmonStyleFields[field] }

// IsAuditStyleField reports whether the native eBPF audit records carry field.
func IsAuditStyleField(field string) bool {
	return auditStyleFields[field] || auditArgField.MatchString(field)
}
