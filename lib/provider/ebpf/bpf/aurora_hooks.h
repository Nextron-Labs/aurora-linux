// SPDX-License-Identifier: GPL-2.0
// aurora_hooks.h — event layout, ring buffer and helpers shared by the
// security-hook programs (audit_hooks.c) and the syscall-entry hooks
// (syscall_hooks.c). Userland loads both objects with the same ring buffer
// (map replacement), so the definitions here MUST stay identical.
//
// Operation codes MUST match hookOp* in audit_hooks.go.

#ifndef AURORA_HOOKS_H
#define AURORA_HOOKS_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define HOOK_PATH     512
#define NAME_KEY      32

#define FMODE_READ  0x1
#define FMODE_WRITE 0x2
#define O_TRUNC     01000
#define S_IFMT      0170000
#define S_IFREG     0100000
#define S_IFCHR     0020000
#define S_IFBLK     0060000
#define S_IFIFO     0010000
#define AF_INET     2
#define AF_INET6    10

// watch permission bits (auditd -p r/w/a)
#define PERM_R 1
#define PERM_W 2
#define PERM_A 4

// watch flags
#define W_FILE 1 // the inode itself is watched
#define W_DIR  2 // creations/removals of entries inside this directory
#define W_RECURSIVE 4 // ... and inside its subdirectories (up to RECURSIVE_DEPTH)
#define RECURSIVE_DEPTH 4

enum hook_op {
	HOP_OPEN = 101,
	HOP_CREATE,
	HOP_MKNOD_SPECIAL,
	HOP_MKDIR,
	HOP_UNLINK,
	HOP_RMDIR,
	HOP_RENAME,
	HOP_LINK,
	HOP_SYMLINK,
	HOP_SETATTR,
	HOP_TRUNCATE,
	HOP_CONNECT,
	HOP_SYSLOG,
	HOP_INIT_MODULE,
	HOP_FINIT_MODULE,
	HOP_SYSINFO,
	HOP_PERSONALITY,
	HOP_MEMFD_CREATE,
	HOP_DELETE_MODULE,
};

// hook_event.flags
#define HOOK_F_PATH1_PARTIAL 1 // path walk stopped before the root
#define HOOK_F_PATH2_PARTIAL 2
#define HOOK_F_COMPAT        4 // 32-bit (compat) syscall entry

struct hook_event {
	__u64 timestamp_ns;
	__u64 start_ns;   // thread-group leader start time
	__u64 exec_id;    // leader's self_exec_id (changes on every execve)
	__u32 op;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 euid;
	__u32 egid;
	__u32 watch_id;   // watch entry of the hit (0 = name/dir match)
	__u32 watch_id2;
	__u32 access;     // PERM_* for opens, syslog type, ...
	__u32 mode;
	__u32 path_len;
	__u32 path2_len;
	__u32 flags;      // HOOK_F_*
	char  comm[TASK_COMM_LEN];
	char  path[HOOK_PATH];
	char  path2[HOOK_PATH];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} hook_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hook_lost_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct hook_event);
} hook_scratch SEC(".maps");



static __always_inline int is_self(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&self_pids, &pid) != NULL;
}

// leader_exec_id reads task->self_exec_id at its real width (u32 before 5.9).
static __always_inline __u64 leader_exec_id(struct task_struct *leader)
{
	if (bpf_core_field_size(leader->self_exec_id) == 4) {
		__u32 v = 0;
		BPF_CORE_READ_INTO(&v, leader, self_exec_id);
		return v;
	}
	__u64 v = 0;
	BPF_CORE_READ_INTO(&v, leader, self_exec_id);
	return v;
}

static __always_inline struct hook_event *begin(__u32 op)
{
	__u32 zero = 0;
	struct hook_event *e = bpf_map_lookup_elem(&hook_scratch, &zero);
	if (!e)
		return NULL;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->timestamp_ns = bpf_ktime_get_ns();
	e->start_ns = BPF_CORE_READ(leader, start_boottime);
	e->exec_id = leader_exec_id(leader);
	e->op = op;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = uid_gid & 0xFFFFFFFF;
	e->gid = uid_gid >> 32;
	e->euid = BPF_CORE_READ(task, cred, euid.val);
	e->egid = BPF_CORE_READ(task, cred, egid.val);
	e->watch_id = 0;
	e->watch_id2 = 0;
	e->access = 0;
	e->mode = 0;
	e->path_len = 0;
	e->path2_len = 0;
	e->flags = 0;
	e->path[0] = 0;
	e->path2[0] = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline int submit(struct hook_event *e)
{
	if (bpf_ringbuf_output(&hook_events, e, sizeof(*e), 0) != 0) {
		__u32 k = 0;
		__u64 *c = bpf_map_lookup_elem(&hook_lost_events, &k);
		if (c)
			__sync_fetch_and_add(c, 1);
	}
	return 0;
}

#endif
