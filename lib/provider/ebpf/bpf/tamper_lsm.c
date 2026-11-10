// SPDX-License-Identifier: GPL-2.0
// tamper_lsm.c — optional enforcement (--tamper-protection enforce).
//
// BPF-LSM hooks (needs CONFIG_BPF_LSM and "bpf" in the active LSM list).
// Denied, unless the actor is Aurora itself, the service manager (pid 1) or
// Aurora's real parent (container shim / supervisor, so `docker stop` and
// Kubernetes termination keep working):
//   * signals to Aurora (all paths reach task_kill), SIGIO delivery to it
//   * ptrace attach (covers process_vm_*, /proc/PID/mem, pidfd_getfd)
//   * nice/scheduler/ioprio changes on Aurora
//   * writes to Aurora's cgroup and /proc control files
//   * fds to Aurora's own BPF programs/maps/links (blocks detach, replace and
//     map tampering) — other software's BPF objects are not affected
//   * loading or attaching tracing-class programs by other processes, which
//     could blind or kill the sensors (bpf_probe_write_user,
//     bpf_override_return, bpf_send_signal, sched_ext). pid 1 may still load
//     (systemd's own BPF-LSM programs).
// Every denial is reported through the ring buffer.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define EPERM 1
#define PTRACE_MODE_ATTACH 0x02
#define FMODE_WRITE 0x2

enum lsm_kind {
	LK_SIGNAL = 1,
	LK_PTRACE,
	LK_BPF,
	LK_SIGIO,
	LK_SCHED,
	LK_CONTROL_WRITE,
};

struct tamper_lsm_event {
	__u64 timestamp_ns;
	__u32 kind;
	__u32 pid;
	__u32 uid;
	__u32 target;
	__u32 arg;
	__u32 arg2;
	char  comm[TASK_COMM_LEN];
};

struct inode_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} lsm_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} lsm_protected SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} lsm_prog_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} lsm_map_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} lsm_link_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct inode_key);
	__type(value, __u8);
} lsm_protected_inodes SEC(".maps");

static __always_inline __u32 cur_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline int is_protected(__u32 pid)
{
	return bpf_map_lookup_elem(&lsm_protected, &pid) != NULL;
}

// Aurora itself, pid 1, or the protected task's real parent (systemd, a
// container shim or a supervisor), so legitimate stop/restart keeps working.
// target may be NULL when the hook has no task (control-file writes).
static __always_inline int trusted_actor(struct task_struct *target)
{
	__u32 me = cur_tgid();
	if (me == 1 || is_protected(me))
		return 1;
	if (target && me == BPF_CORE_READ(target, real_parent, tgid))
		return 1;
	return 0;
}

static __always_inline int deny(__u32 kind, __u32 target, __u32 arg, __u32 arg2)
{
	struct tamper_lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
	if (e) {
		e->timestamp_ns = bpf_ktime_get_ns();
		e->kind = kind;
		e->pid = cur_tgid();
		e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
		e->target = target;
		e->arg = arg;
		e->arg2 = arg2;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	return -EPERM;
}

SEC("lsm/task_kill")
int BPF_PROG(tamper_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig,
	     const struct cred *cred)
{
	__u32 target = BPF_CORE_READ(p, tgid);
	if (sig == 0 || !is_protected(target) || trusted_actor(p))
		return 0;
	return deny(LK_SIGNAL, target, sig, 0);
}

SEC("lsm/file_send_sigiotask")
int BPF_PROG(tamper_sigiotask, struct task_struct *tsk, struct fown_struct *fown, int sig)
{
	__u32 target = BPF_CORE_READ(tsk, tgid);
	if (!is_protected(target) || is_protected(cur_tgid()))
		return 0;
	return deny(LK_SIGIO, target, sig, 0);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(tamper_ptrace_access, struct task_struct *child, unsigned int mode)
{
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	__u32 target = BPF_CORE_READ(child, tgid);
	if (!is_protected(target) || is_protected(cur_tgid()))
		return 0;
	return deny(LK_PTRACE, target, mode, 0);
}

static __always_inline int sched_change(struct task_struct *p, __u32 what)
{
	__u32 target = BPF_CORE_READ(p, tgid);
	if (!is_protected(target) || trusted_actor(p))
		return 0;
	return deny(LK_SCHED, target, what, 0);
}

SEC("lsm/task_setnice")
int BPF_PROG(tamper_setnice, struct task_struct *p, int nice)
{
	return sched_change(p, 1);
}

SEC("lsm/task_setscheduler")
int BPF_PROG(tamper_setscheduler, struct task_struct *p)
{
	return sched_change(p, 2);
}

SEC("lsm/task_setioprio")
int BPF_PROG(tamper_setioprio, struct task_struct *p, int ioprio)
{
	return sched_change(p, 3);
}

SEC("lsm/file_open")
int BPF_PROG(tamper_file_open, struct file *file)
{
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	struct inode_key k = {};
	k.ino = BPF_CORE_READ(inode, i_ino);
	k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	if (!bpf_map_lookup_elem(&lsm_protected_inodes, &k) || trusted_actor(NULL))
		return 0;
	return deny(LK_CONTROL_WRITE, 0, 0, 0);
}

SEC("lsm/bpf_map")
int BPF_PROG(tamper_bpf_map, struct bpf_map *map)
{
	__u32 id = BPF_CORE_READ(map, id);
	if (!bpf_map_lookup_elem(&lsm_map_ids, &id) || is_protected(cur_tgid()))
		return 0;
	return deny(LK_BPF, 0, BPF_MAP_GET_FD_BY_ID, id);
}

SEC("lsm/bpf_prog")
int BPF_PROG(tamper_bpf_prog, struct bpf_prog *prog)
{
	__u32 id = BPF_CORE_READ(prog, aux, id);
	if (!bpf_map_lookup_elem(&lsm_prog_ids, &id) || is_protected(cur_tgid()))
		return 0;
	return deny(LK_BPF, 0, BPF_PROG_GET_FD_BY_ID, id);
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

SEC("lsm/bpf")
int BPF_PROG(tamper_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	__u32 me = cur_tgid();
	if (is_protected(me))
		return 0;

	switch (cmd) {
	case BPF_PROG_LOAD: {
		__u32 t = BPF_CORE_READ(attr, prog_type);
		if (me != 1 && tracing_type(t))
			return deny(LK_BPF, 0, cmd, t);
		return 0;
	}
	case BPF_LINK_CREATE: {
		__u32 a = BPF_CORE_READ(attr, link_create.attach_type);
		if (me != 1 && tracing_attach(a))
			return deny(LK_BPF, 0, cmd, a);
		return 0;
	}
	case BPF_RAW_TRACEPOINT_OPEN:
		if (me != 1)
			return deny(LK_BPF, 0, cmd, 0);
		return 0;
	case BPF_LINK_GET_FD_BY_ID: {
		__u32 id = BPF_CORE_READ(attr, link_id);
		if (bpf_map_lookup_elem(&lsm_link_ids, &id))
			return deny(LK_BPF, 0, cmd, id);
		return 0;
	}
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
