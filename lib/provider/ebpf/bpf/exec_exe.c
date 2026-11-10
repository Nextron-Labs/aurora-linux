// SPDX-License-Identifier: GPL-2.0
// exec_exe.c — optional companion of exec_monitor.c: resolves the canonical
// path of every newly exec'd image in-kernel (mm->exe_file), so Image/exe do
// not depend on reading /proc after the process may have exited or been
// replaced. Kept separate so exec_monitor.c still loads on kernels without
// bpf_loop (5.17+); userland then falls back to /proc/PID/exe.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "aurora_path.h"

#define EXE_PATH 512

struct exe_info {
	__u64 exec_id;
	__u32 len;
	__u32 pad;
	char  path[EXE_PATH];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32); // tgid
	__type(value, struct exe_info);
} exe_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exe_info);
} exe_scratch SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int exec_exe_path(void *ctx)
{
	__u32 zero = 0;
	struct exe_info *info = bpf_map_lookup_elem(&exe_scratch, &zero);
	if (!info)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct file *exe = BPF_CORE_READ(task, mm, exe_file);
	if (!exe)
		return 0;
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (bpf_core_field_size(leader->self_exec_id) == 4) {
		__u32 v = 0;
		BPF_CORE_READ_INTO(&v, leader, self_exec_id);
		info->exec_id = v;
	} else {
		BPF_CORE_READ_INTO(&info->exec_id, leader, self_exec_id);
	}
	info->pad = 0;
	__u32 complete = 0;
	info->len = ap_resolve(BPF_CORE_READ(exe, f_path.mnt), BPF_CORE_READ(exe, f_path.dentry), NULL,
			       info->path, EXE_PATH, &complete);
	if (!complete)
		return 0; // partial: userland falls back to /proc/PID/exe
	if (info->len == 0)
		return 0;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&exe_paths, &pid, info, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
