// SPDX-License-Identifier: GPL-2.0
// filetime_monitor.c — BPF programs for tracepoint/syscalls/sys_{enter,exit}_utimensat
//
// Detects file timestamp modification (timestomping). Pairs sys_enter_utimensat
// (capture filename, dirfd, new timestamps) with sys_exit_utimensat (check
// return value). Only successful calls are emitted.
//
// Maps to Sysmon Event ID 2 (FileCreateTime changed).

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME 256

// Special tv_nsec values defined in <linux/stat.h>
#define UTIME_NOW  0x3FFFFFFF
#define UTIME_OMIT 0x3FFFFFFE

// Kernel timespec used by utimensat(2).
struct bpf_timespec {
	__s64 tv_sec;
	__s64 tv_nsec;
};

// Temporary storage for in-flight utimensat calls, keyed by pid_tgid.
struct filetime_args {
	char  filename[MAX_FILENAME];
	__u32 filename_len;
	__s32 dfd;
	__s32 flags;
	struct bpf_timespec new_atime;
	struct bpf_timespec new_mtime;
	__u8  times_null; // 1 if times pointer was NULL (set to current time)
};

struct filetime_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	__s32 dfd;
	__s32 flags;
	char  filename[MAX_FILENAME];
	__u32 filename_len;
	__s64 new_atime_sec;
	__s64 new_atime_nsec;
	__s64 new_mtime_sec;
	__s64 new_mtime_nsec;
	__u8  times_null;
	__u8  pad[3];
};

// Per-CPU hash to correlate enter/exit
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct filetime_args);
} utimensat_args SEC(".maps");

// Ring buffer for filetime events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 4 MB
} filetime_events SEC(".maps");

// Lost event counter
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} filetime_lost_events SEC(".maps");

// PIDs to exclude (Aurora itself).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_pids SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_utimensat")
int trace_sys_enter_utimensat(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return 0;

	// utimensat args: dfd(0), filename(1), utimes(2), flags(3)
	struct filetime_args args = {};
	args.dfd = (int)ctx->args[0];
	args.flags = (int)ctx->args[3];

	// Read filename from userspace
	const char *fname = (const char *)ctx->args[1];
	if (fname) {
		int ret = bpf_probe_read_user_str(args.filename, sizeof(args.filename), fname);
		if (ret <= 0)
			return 0; // can't read filename, skip
		args.filename_len = ret;
	} else {
		// NULL filename means operate on dirfd itself (futimens-like)
		args.filename[0] = '\0';
		args.filename_len = 0;
	}

	// Read the new timestamps from userspace
	const void *utimes = (const void *)ctx->args[2];
	if (utimes) {
		struct bpf_timespec ts[2] = {};
		int ret = bpf_probe_read_user(ts, sizeof(ts), utimes);
		if (ret == 0) {
			args.new_atime = ts[0];
			args.new_mtime = ts[1];
		}
		args.times_null = 0;
	} else {
		// NULL times = set both to current time
		args.times_null = 1;
	}

	bpf_map_update_elem(&utimensat_args, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_utimensat")
int trace_sys_exit_utimensat(struct trace_event_raw_sys_exit *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return 0;

	struct filetime_args *args = bpf_map_lookup_elem(&utimensat_args, &pid_tgid);
	if (!args)
		return 0;

	// Copy and clean up immediately
	struct filetime_args saved = *args;
	bpf_map_delete_elem(&utimensat_args, &pid_tgid);

	// Check return value: negative = failed
	long retval = ctx->ret;
	if (retval < 0)
		return 0;

	// Reserve ring buffer space
	struct filetime_event *evt = bpf_ringbuf_reserve(&filetime_events, sizeof(*evt), 0);
	if (!evt) {
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&filetime_lost_events, &key);
		if (count)
			__sync_fetch_and_add(count, 1);
		return 0;
	}

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->pid = pid;

	__u64 uid_gid = bpf_get_current_uid_gid();
	evt->uid = uid_gid & 0xFFFFFFFF;

	evt->dfd = saved.dfd;
	evt->flags = saved.flags;

	__builtin_memcpy(evt->filename, saved.filename, MAX_FILENAME);
	evt->filename_len = saved.filename_len;

	evt->new_atime_sec  = saved.new_atime.tv_sec;
	evt->new_atime_nsec = saved.new_atime.tv_nsec;
	evt->new_mtime_sec  = saved.new_mtime.tv_sec;
	evt->new_mtime_nsec = saved.new_mtime.tv_nsec;
	evt->times_null     = saved.times_null;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
