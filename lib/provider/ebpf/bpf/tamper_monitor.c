// SPDX-License-Identifier: GPL-2.0
// tamper_monitor.c — detects attempts to stop, inspect or reconfigure Aurora.
//
// Tracepoints fire for signals, ptrace/process_vm_* and bpf(2) management
// commands aimed at protected processes (Aurora itself). Events from the
// protected process are ignored. Detection only; see tamper_lsm.c for the
// optional enforcement layer.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

enum tamper_kind {
	TK_SIGNAL = 1,
	TK_PTRACE,
	TK_VM_WRITE,
	TK_VM_READ,
	TK_BPF_MGMT,   // detach / link update / get-fd-by-id / obj get
	TK_BPF_LOAD,   // loading of tracing-class programs (arg2 = prog type)
	TK_PIDFD_GETFD, // duplicating a descriptor out of another process
};

struct tamper_event {
	__u64 timestamp_ns;
	__u32 kind;
	__u32 pid;     // acting process (tgid)
	__u32 uid;
	__u32 target;  // protected pid, 0 for bpf kinds
	__u32 arg;     // signal / ptrace request / bpf cmd
	__u32 arg2;    // bpf prog type
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} tamper_events SEC(".maps");

// PIDs (tgid) to protect; also used to recognise Aurora's own activity.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} protected_pids SEC(".maps");

static __always_inline int is_protected(__u32 pid)
{
	return bpf_map_lookup_elem(&protected_pids, &pid) != NULL;
}

static __always_inline int emit(__u32 kind, __u32 target, __u32 arg, __u32 arg2)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 pid = pt >> 32;
	if (is_protected(pid))
		return 0;

	struct tamper_event *e = bpf_ringbuf_reserve(&tamper_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = pid;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->target = target;
	e->arg = arg;
	e->arg2 = arg2;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int tamper_kill(struct trace_event_raw_sys_enter *ctx)
{
	__u32 target = (__u32)ctx->args[0];
	__u32 sig = (__u32)ctx->args[1];
	if (sig == 0 || !is_protected(target))
		return 0;
	return emit(TK_SIGNAL, target, sig, 0);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tamper_tkill(struct trace_event_raw_sys_enter *ctx)
{
	__u32 target = (__u32)ctx->args[0];
	__u32 sig = (__u32)ctx->args[1];
	if (sig == 0 || !is_protected(target))
		return 0;
	return emit(TK_SIGNAL, target, sig, 0);
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tamper_tgkill(struct trace_event_raw_sys_enter *ctx)
{
	__u32 target = (__u32)ctx->args[0];
	__u32 sig = (__u32)ctx->args[2];
	if (sig == 0 || !is_protected(target))
		return 0;
	return emit(TK_SIGNAL, target, sig, 0);
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tamper_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	__u32 request = (__u32)ctx->args[0];
	__u32 target = (__u32)ctx->args[1];
	if (request == 0 /* PTRACE_TRACEME */ || !is_protected(target))
		return 0;
	return emit(TK_PTRACE, target, request, 0);
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int tamper_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
	__u32 target = (__u32)ctx->args[0];
	if (!is_protected(target))
		return 0;
	return emit(TK_VM_WRITE, target, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int tamper_vm_readv(struct trace_event_raw_sys_enter *ctx)
{
	__u32 target = (__u32)ctx->args[0];
	if (!is_protected(target))
		return 0;
	return emit(TK_VM_READ, target, 0, 0);
}

// pidfd_getfd(2) can steal Aurora's program/link descriptors and close them,
// which silently detaches a sensor. The target is only a pidfd here, so every
// use by a process other than Aurora is reported (the syscall is rare).
SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int tamper_pidfd_getfd(struct trace_event_raw_sys_enter *ctx)
{
	return emit(TK_PIDFD_GETFD, 0, (__u32)ctx->args[1], 0);
}

// bpf(2) commands that can reconfigure or reach other programs' objects.
static __always_inline int mgmt_cmd(__u32 cmd)
{
	switch (cmd) {
	case 7:  // BPF_OBJ_GET
	case 9:  // BPF_PROG_DETACH
	case 13: // BPF_PROG_GET_FD_BY_ID
	case 14: // BPF_MAP_GET_FD_BY_ID
	case 29: // BPF_LINK_UPDATE
	case 30: // BPF_LINK_GET_FD_BY_ID
	case 34: // BPF_LINK_DETACH
		return 1;
	}
	return 0;
}

static __always_inline int tracing_type(__u32 t)
{
	switch (t) {
	case 2:  // KPROBE
	case 5:  // TRACEPOINT
	case 7:  // PERF_EVENT
	case 17: // RAW_TRACEPOINT
	case 24: // RAW_TRACEPOINT_WRITABLE
	case 26: // TRACING
	case 28: // EXT
	case 29: // LSM
		return 1;
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int tamper_bpf(struct trace_event_raw_sys_enter *ctx)
{
	__u32 cmd = (__u32)ctx->args[0];
	if (mgmt_cmd(cmd))
		return emit(TK_BPF_MGMT, 0, cmd, 0);

	if (cmd == 5 /* BPF_PROG_LOAD */) {
		__u32 prog_type = 0;
		bpf_probe_read_user(&prog_type, sizeof(prog_type), (const void *)ctx->args[1]);
		if (tracing_type(prog_type))
			return emit(TK_BPF_LOAD, 0, cmd, prog_type);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
