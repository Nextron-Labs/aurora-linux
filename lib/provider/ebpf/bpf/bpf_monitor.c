// SPDX-License-Identifier: GPL-2.0
// bpf_monitor.c — BPF programs for tracepoint/syscalls/sys_{enter,exit}_bpf
//
// Traces bpf() syscall invocations by pairing sys_enter_bpf (capture command,
// program type, and program name) with sys_exit_bpf (check return value).
// Only successful calls are emitted. For BPF_PROG_LOAD, the program type and
// name are read from the user-space bpf_attr union.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_OBJ_NAME_LEN 16

// Offsets within the bpf_attr union for BPF_PROG_LOAD:
//   prog_type at offset 0   (u32)
//   prog_name at offset 48  (char[16])
#define ATTR_PROG_TYPE_OFF 0
#define ATTR_PROG_NAME_OFF 48

// Temporary storage for in-flight bpf() calls, keyed by pid_tgid.
struct bpf_call_args {
	__u32 cmd;
	__u32 prog_type;
	char  prog_name[BPF_OBJ_NAME_LEN];
};

struct bpf_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	__u32 cmd;
	__u32 prog_type;
	__s64 ret_val;        // fd on success, negative errno on failure
	char  prog_name[BPF_OBJ_NAME_LEN];
};

// Per-CPU hash to correlate enter/exit
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct bpf_call_args);
} bpf_args SEC(".maps");

// Ring buffer for bpf events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024); // 2 MB
} bpf_events SEC(".maps");

// Lost event counter
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} bpf_lost_events SEC(".maps");

// PIDs that should be excluded from telemetry (Aurora itself).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_pids SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_sys_enter_bpf(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return 0;

	// args: cmd(0), attr(1), size(2)
	__u32 cmd = (__u32)ctx->args[0];
	const void *uattr = (const void *)ctx->args[1];

	struct bpf_call_args args = {};
	args.cmd = cmd;

	// For BPF_PROG_LOAD (cmd=5), read program type and name from uattr
	if (cmd == 5 && uattr) {
		bpf_probe_read_user(&args.prog_type, sizeof(args.prog_type),
				    uattr + ATTR_PROG_TYPE_OFF);
		bpf_probe_read_user_str(args.prog_name, sizeof(args.prog_name),
					uattr + ATTR_PROG_NAME_OFF);
	}

	bpf_map_update_elem(&bpf_args, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_bpf")
int trace_sys_exit_bpf(struct trace_event_raw_sys_exit *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return 0;

	struct bpf_call_args *args = bpf_map_lookup_elem(&bpf_args, &pid_tgid);
	if (!args)
		return 0;

	// Clean up immediately
	struct bpf_call_args saved = *args;
	bpf_map_delete_elem(&bpf_args, &pid_tgid);

	long retval = ctx->ret;

	// Only emit successful calls (retval >= 0)
	if (retval < 0)
		return 0;

	struct bpf_event *evt = bpf_ringbuf_reserve(&bpf_events, sizeof(*evt), 0);
	if (!evt) {
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&bpf_lost_events, &key);
		if (count)
			__sync_fetch_and_add(count, 1);
		return 0;
	}

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->pid = pid;

	__u64 uid_gid = bpf_get_current_uid_gid();
	evt->uid = uid_gid & 0xFFFFFFFF;

	evt->cmd = saved.cmd;
	evt->prog_type = saved.prog_type;
	evt->ret_val = retval;

	__builtin_memcpy(evt->prog_name, saved.prog_name, BPF_OBJ_NAME_LEN);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
