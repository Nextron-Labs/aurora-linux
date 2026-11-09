// SPDX-License-Identifier: GPL-2.0
// tamper_hooks.c — anti-tamper detection on LSM security hooks (fentry).
//
// The hooks receive the kernel's resolved target task / object, so they cover
// every entry point: kill/tkill/tgkill, process-group kills, pidfd_send_signal,
// rt_(tg)sigqueueinfo, SIGIO delivery, compat syscalls, thread-id targets,
// ptrace/process_vm_*/pidfd_getfd//proc/PID/mem, fd acquisition for Aurora's
// own BPF objects, and writes to Aurora's cgroup / procfs control files.
// They fire after the kernel's own permission checks, so unprivileged users
// cannot generate alert noise. Detection only (always returns 0); see
// tamper_lsm.c for enforcement.
//
// Kinds MUST match tk* in tamper.go.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aurora_path.h"

#define TASK_COMM_LEN 16
#define PTRACE_MODE_ATTACH 0x02
#define FMODE_WRITE 0x2
#define TAMPER_PATH 256

enum tamper_kind {
	TK_SIGNAL = 1,
	TK_PTRACE,
	TK_VM_WRITE,      // tracepoint fallback only
	TK_VM_READ,       // tracepoint fallback only
	TK_BPF_MGMT,      // fd acquisition / detach / update of Aurora's objects
	TK_BPF_LOAD,      // tracing-class program load
	TK_PIDFD_GETFD,   // tracepoint fallback only
	TK_BPF_ATTACH,    // tracing attach of an existing program
	TK_SIGIO,         // signal through F_SETOWN/F_SETSIG
	TK_SCHED,         // nice / scheduler / ioprio change
	TK_CONTROL_WRITE, // write to Aurora's cgroup or /proc control files
};

struct tamper_event {
	__u64 timestamp_ns;
	__u32 kind;
	__u32 pid;
	__u32 uid;
	__u32 target;
	__u32 arg;
	__u32 arg2;
	char  comm[TASK_COMM_LEN];
	char  path[TAMPER_PATH];
};

// Survives Aurora's death (pinned): the last fatal signal sent to it.
struct last_fatal {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	__u32 sig;
	__u32 target;
	char  comm[TASK_COMM_LEN];
};

struct inode_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} tamper_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} tamper_lost SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} protected_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} aurora_prog_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} aurora_map_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} aurora_link_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct inode_key);
	__type(value, __u8);
} protected_inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct last_fatal);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} aurora_last_fatal SEC(".maps");

static __always_inline int is_protected(__u32 pid)
{
	return bpf_map_lookup_elem(&protected_pids, &pid) != NULL;
}

static __always_inline __u32 cur_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline struct tamper_event *reserve(__u32 kind, __u32 target, __u32 arg, __u32 arg2)
{
	struct tamper_event *e = bpf_ringbuf_reserve(&tamper_events, sizeof(*e), 0);
	if (!e) {
		__u32 k = 0;
		__u64 *c = bpf_map_lookup_elem(&tamper_lost, &k);
		if (c)
			__sync_fetch_and_add(c, 1);
		return NULL;
	}
	e->timestamp_ns = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = cur_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->target = target;
	e->arg = arg;
	e->arg2 = arg2;
	e->path[0] = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline int emit(__u32 kind, __u32 target, __u32 arg, __u32 arg2)
{
	struct tamper_event *e = reserve(kind, target, arg, arg2);
	if (e)
		bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int fatal_signal(int sig)
{
	switch (sig) {
	case 0:
	case 17: // SIGCHLD
	case 18: // SIGCONT
	case 23: // SIGURG
	case 28: // SIGWINCH
		return 0;
	}
	return 1;
}

SEC("fentry/security_task_kill")
int BPF_PROG(tamper_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig)
{
	__u32 target = BPF_CORE_READ(p, tgid);
	if (sig == 0 || !is_protected(target))
		return 0;
	__u32 sender = cur_tgid();
	if (is_protected(sender))
		return 0;

	if (fatal_signal(sig)) {
		__u32 zero = 0;
		struct last_fatal *lf = bpf_map_lookup_elem(&aurora_last_fatal, &zero);
		if (lf) {
			lf->timestamp_ns = bpf_ktime_get_ns();
			lf->pid = sender;
			lf->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
			lf->sig = sig;
			lf->target = target;
			bpf_get_current_comm(&lf->comm, sizeof(lf->comm));
		}
	}
	return emit(TK_SIGNAL, target, sig, 0);
}

SEC("fentry/security_file_send_sigiotask")
int BPF_PROG(tamper_sigiotask, struct task_struct *tsk, struct fown_struct *fown, int sig)
{
	__u32 target = BPF_CORE_READ(tsk, tgid);
	if (!is_protected(target) || is_protected(cur_tgid()))
		return 0;
	return emit(TK_SIGIO, target, sig, 0);
}

SEC("fentry/security_ptrace_access_check")
int BPF_PROG(tamper_ptrace, struct task_struct *child, unsigned int mode)
{
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	__u32 target = BPF_CORE_READ(child, tgid);
	if (!is_protected(target) || is_protected(cur_tgid()))
		return 0;
	return emit(TK_PTRACE, target, mode, 0);
}

static __always_inline int sched_change(struct task_struct *p, __u32 what)
{
	__u32 target = BPF_CORE_READ(p, tgid);
	if (!is_protected(target) || is_protected(cur_tgid()))
		return 0;
	return emit(TK_SCHED, target, what, 0);
}

SEC("fentry/security_task_setnice")
int BPF_PROG(tamper_setnice, struct task_struct *p, int nice)
{
	return sched_change(p, 1);
}

SEC("fentry/security_task_setscheduler")
int BPF_PROG(tamper_setscheduler, struct task_struct *p)
{
	return sched_change(p, 2);
}

SEC("fentry/security_task_setioprio")
int BPF_PROG(tamper_setioprio, struct task_struct *p, int ioprio)
{
	return sched_change(p, 3);
}

static __always_inline int tracing_type(__u32 t)
{
	switch (t) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_EXT:
	case BPF_PROG_TYPE_LSM:
	case BPF_PROG_TYPE_STRUCT_OPS:
		return 1;
	}
	return 0;
}

static __always_inline int tracing_attach(__u32 a)
{
	switch (a) {
	case BPF_TRACE_RAW_TP:
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
	case BPF_MODIFY_RETURN:
	case BPF_LSM_MAC:
	case BPF_PERF_EVENT:
	case BPF_TRACE_KPROBE_MULTI:
		return 1;
	}
	return 0;
}

SEC("fentry/security_bpf")
int BPF_PROG(tamper_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	if (is_protected(cur_tgid()))
		return 0;

	switch (cmd) {
	case BPF_PROG_LOAD: {
		__u32 t = BPF_CORE_READ(attr, prog_type);
		if (tracing_type(t))
			return emit(TK_BPF_LOAD, 0, cmd, t);
		return 0;
	}
	case BPF_LINK_CREATE: {
		__u32 a = BPF_CORE_READ(attr, link_create.attach_type);
		if (tracing_attach(a))
			return emit(TK_BPF_ATTACH, 0, cmd, a);
		return 0;
	}
	case BPF_RAW_TRACEPOINT_OPEN:
		return emit(TK_BPF_ATTACH, 0, cmd, 0);
	case BPF_LINK_GET_FD_BY_ID: {
		__u32 id = BPF_CORE_READ(attr, link_id);
		if (bpf_map_lookup_elem(&aurora_link_ids, &id))
			return emit(TK_BPF_MGMT, 0, cmd, id);
		return 0;
	}
	}
	return 0;
}

// Called whenever an fd to an existing map/program is handed out
// (GET_FD_BY_ID, OBJ_GET of a pin): flags any access to Aurora's objects.
SEC("fentry/security_bpf_map")
int BPF_PROG(tamper_bpf_map, struct bpf_map *map)
{
	if (is_protected(cur_tgid()))
		return 0;
	__u32 id = BPF_CORE_READ(map, id);
	if (!bpf_map_lookup_elem(&aurora_map_ids, &id))
		return 0;
	return emit(TK_BPF_MGMT, 0, BPF_MAP_GET_FD_BY_ID, id);
}

SEC("fentry/security_bpf_prog")
int BPF_PROG(tamper_bpf_prog, struct bpf_prog *prog)
{
	if (is_protected(cur_tgid()))
		return 0;
	__u32 id = BPF_CORE_READ(prog, aux, id);
	if (!bpf_map_lookup_elem(&aurora_prog_ids, &id))
		return 0;
	return emit(TK_BPF_MGMT, 0, BPF_PROG_GET_FD_BY_ID, id);
}

// Writes to Aurora's cgroup control files (cgroup.kill, cgroup.freeze,
// memory.max, ...) or /proc/<aurora>/oom_score_adj.
SEC("fentry/security_file_open")
int BPF_PROG(tamper_file_open, struct file *file)
{
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	struct inode_key k = {};
	k.ino = BPF_CORE_READ(inode, i_ino);
	k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	if (!bpf_map_lookup_elem(&protected_inodes, &k) || is_protected(cur_tgid()))
		return 0;
	struct tamper_event *e = reserve(TK_CONTROL_WRITE, 0, 0, 0);
	if (!e)
		return 0;
	ap_resolve(BPF_CORE_READ(file, f_path.mnt), BPF_CORE_READ(file, f_path.dentry), NULL,
		   e->path, TAMPER_PATH, NULL);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
