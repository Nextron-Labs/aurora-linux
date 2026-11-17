// SPDX-License-Identifier: GPL-2.0
// exec_monitor.c — BPF program for tracepoint/sched/sched_process_exec
//
// Captures minimal data per successful execve: pid, ppid, uid, gid, comm, filename.
// The raw argv block (NUL-separated, as laid out by the kernel at exec time) is
// captured in-kernel so short-lived processes still get a faithful EXECVE
// record. All richer fields (parent image, username, cwd) are reconstructed
// in userland.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN  16
#define MAX_FILENAME   256
#define MAX_ARGS       4096

struct exec_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	char  comm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME];
	__u32 filename_len;
	__u32 euid;
	__u32 egid;
	__u32 args_len;
	__u64 start_ns; // thread-group leader start time (CLOCK_BOOTTIME): identifies the process across pid reuse
	__u64 exec_id;  // leader's self_exec_id: changes on every execve
	// Last, and only args_len bytes of it are submitted: a typical exec
	// takes ~400 bytes of the ring instead of the full 4.4 KB.
	char  args[MAX_ARGS];
};


// Ring buffer for delivering events to userland.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024); // 8 MB default
} events SEC(".maps");

// Counter for dropped events when ring buffer is full.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost_events SEC(".maps");

// PIDs that should be excluded from telemetry (Aurora itself).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_pids SEC(".maps");

// The event is built here, then copied to the ring at its real size.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_event);
} exec_scratch SEC(".maps");

static __always_inline void count_lost(void) {
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&lost_events, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return 0;

	struct exec_event *evt;

	__u32 zero = 0;
	evt = bpf_map_lookup_elem(&exec_scratch, &zero);
	if (!evt)
		return 0;

	// Timestamp
	evt->timestamp_ns = bpf_ktime_get_ns();

	// PID and PPID
	evt->pid = pid;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent;
	parent = BPF_CORE_READ(task, real_parent);
	evt->ppid = BPF_CORE_READ(parent, tgid);

	// UID and GID
	__u64 uid_gid = bpf_get_current_uid_gid();
	evt->uid = uid_gid & 0xFFFFFFFF;
	evt->gid = uid_gid >> 32;

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	evt->start_ns = BPF_CORE_READ(leader, start_boottime);
	if (bpf_core_field_size(leader->self_exec_id) == 4) { // u32 before 5.9
		__u32 v = 0;
		BPF_CORE_READ_INTO(&v, leader, self_exec_id);
		evt->exec_id = v;
	} else {
		BPF_CORE_READ_INTO(&evt->exec_id, leader, self_exec_id);
	}

	// Effective credentials (auditd euid/egid)
	evt->euid = BPF_CORE_READ(task, cred, euid.val);
	evt->egid = BPF_CORE_READ(task, cred, egid.val);

	// argv block of the freshly exec'd image (mm->arg_start..arg_end)
	evt->args_len = 0;
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm) {
		unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
		unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
		if (arg_end > arg_start) {
			unsigned long len = arg_end - arg_start;
			if (len > MAX_ARGS)
				len = MAX_ARGS;
			if (bpf_probe_read_user(evt->args, len, (void *)arg_start) == 0)
				evt->args_len = len;
		}
	}

	// comm (task name, max 16 bytes)
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	// filename from bprm->filename via the tracepoint data
	// The tracepoint provides the filename offset in __data.
	unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
	int ret = bpf_probe_read_kernel_str(
		evt->filename,
		sizeof(evt->filename),
		(void *)ctx + fname_off
	);
	if (ret > 0) {
		evt->filename_len = ret;
	} else {
		evt->filename[0] = '\0';
		evt->filename_len = 0;
	}

	__u64 n = evt->args_len;
	if (n > MAX_ARGS)
		n = MAX_ARGS;
	if (bpf_ringbuf_output(&events, evt, offsetof(struct exec_event, args) + n, 0) != 0)
		count_lost(); // ring full
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
