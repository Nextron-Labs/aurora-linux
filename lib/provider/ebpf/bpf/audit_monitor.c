// SPDX-License-Identifier: GPL-2.0
// audit_monitor.c — syscall tracepoints that replace the auditd rules required
// by the SigmaHQ linux/auditd rule set.
//
// Every program fires on sys_enter_<syscall>, captures the raw arguments that
// auditd would have logged (path strings, syscall arguments, sockaddr) and
// pushes one audit_event to a shared ring buffer. Userland turns the events
// into auditd-shaped SYSCALL / PATH records.
//
// File-path syscalls are pre-filtered in-kernel with an LPM trie of path
// prefixes (watch_prefixes, populated from userland) so that the bulk of
// uninteresting opens never reach the ring buffer. Relative paths always pass
// the filter because they can only be resolved in userland.
//
// The operation codes below MUST be kept in sync with auditOp* in audit.go.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN   16
#define MAX_PATH        256
#define WATCH_KEY_BYTES 64
#define MAX_WATCHES     512

#define AF_INET  2
#define AF_INET6 10

enum audit_op {
	AOP_OPEN = 1,
	AOP_OPENAT,
	AOP_OPENAT2,
	AOP_CREAT,
	AOP_TRUNCATE,
	AOP_MKDIR,
	AOP_MKDIRAT,
	AOP_RMDIR,
	AOP_UNLINK,
	AOP_UNLINKAT,
	AOP_RENAME,
	AOP_RENAMEAT,
	AOP_RENAMEAT2,
	AOP_LINK,
	AOP_LINKAT,
	AOP_SYMLINK,
	AOP_SYMLINKAT,
	AOP_CHMOD,
	AOP_FCHMODAT,
	AOP_FCHMODAT2,
	AOP_CHOWN,
	AOP_LCHOWN,
	AOP_FCHOWNAT,
	AOP_UTIMENSAT,
	AOP_MKNOD,
	AOP_MKNODAT,
	AOP_SYSINFO,
	AOP_SYSLOG,
	AOP_PERSONALITY,
	AOP_MEMFD_CREATE,
	AOP_INIT_MODULE,
	AOP_FINIT_MODULE,
	AOP_DELETE_MODULE,
	AOP_CONNECT,
};

struct audit_event {
	__u64 timestamp_ns;
	__u32 op;
	__u32 nr;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 euid;
	__u32 egid;
	__s32 dfd;
	__s32 dfd2;
	__u32 flags;
	__u32 path_len;
	__u32 path2_len;
	__u32 pad;
	__u64 args[4];
	char  comm[TASK_COMM_LEN];
	char  path[MAX_PATH];
	char  path2[MAX_PATH];
	__u64 start_ns; // task start time (CLOCK_BOOTTIME), identifies the process across pid reuse
};

struct watch_key {
	__u32 prefixlen; // in bits
	__u8  data[WATCH_KEY_BYTES];
};

// Ring buffer shared by all audit programs.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} audit_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} audit_lost_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_pids SEC(".maps");

// Per-CPU scratch space: struct audit_event does not fit on the BPF stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct audit_event);
} audit_scratch SEC(".maps");

// Path prefixes worth reporting. Value 1 means "only if the path also contains
// a hidden component ('/.')", used for /home/ so dotfile watches stay cheap.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_WATCHES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct watch_key);
	__type(value, __u8);
} watch_prefixes SEC(".maps");

static __always_inline unsigned long sys_arg(struct trace_event_raw_sys_enter *ctx, int i)
{
	switch (i) {
	case 0: return ctx->args[0];
	case 1: return ctx->args[1];
	case 2: return ctx->args[2];
	case 3: return ctx->args[3];
	case 4: return ctx->args[4];
	case 5: return ctx->args[5];
	}
	return 0;
}

static __always_inline int has_hidden_component(const char *p)
{
	for (int i = 1; i < MAX_PATH - 1; i++) {
		char c = p[i];
		if (c == '\0')
			return 0;
		if (c == '/' && p[i + 1] == '.')
			return 1;
	}
	return 0;
}

// head_verdict decides from the first WATCH_KEY_BYTES of a user-space path
// whether it can be interesting, without paying for the full 256-byte copy
// on the (vast majority of) uninteresting opens:
//   0 = skip, 1 = forward, 2 = forward only if the path has a hidden component.
// Relative paths always pass (only userland can resolve them). Note the
// string is NUL-terminated inside the 64 bytes, so userland never registers
// prefixes longer than WATCH_KEY_BYTES-1.
static __always_inline int head_verdict(const char *user_path)
{
	struct watch_key key = {};
	key.prefixlen = WATCH_KEY_BYTES * 8;
	long n = bpf_probe_read_user_str(key.data, WATCH_KEY_BYTES, user_path);
	if (n <= 1)
		return 0;
	if (key.data[0] != '/')
		return 1;

	__u8 *needs_hidden = bpf_map_lookup_elem(&watch_prefixes, &key);
	if (!needs_hidden)
		return 0;
	return *needs_hidden ? 2 : 1;
}

static __always_inline void fill_task(struct audit_event *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->timestamp_ns = bpf_ktime_get_ns();
	e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
	e->ppid = BPF_CORE_READ(parent, tgid);
	e->uid = uid_gid & 0xFFFFFFFF;
	e->gid = uid_gid >> 32;
	e->euid = BPF_CORE_READ(task, cred, euid.val);
	e->egid = BPF_CORE_READ(task, cred, egid.val);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int submit(struct audit_event *e)
{
	if (bpf_ringbuf_output(&audit_events, e, sizeof(*e), 0) != 0) {
		__u32 k = 0;
		__u64 *c = bpf_map_lookup_elem(&audit_lost_events, &k);
		if (c)
			__sync_fetch_and_add(c, 1);
	}
	return 0;
}

// begin reserves the per-CPU scratch event. nargs is the number of arguments
// of the traced syscall: newer kernels refuse to attach a tracepoint program
// that reads ctx->args[] beyond the syscall's real argument count.
static __always_inline struct audit_event *begin(struct trace_event_raw_sys_enter *ctx, __u32 op,
						 int nargs)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (bpf_map_lookup_elem(&self_pids, &pid))
		return NULL;

	__u32 zero = 0;
	struct audit_event *e = bpf_map_lookup_elem(&audit_scratch, &zero);
	if (!e)
		return NULL;

	e->op = op;
	e->nr = (__u32)ctx->id;
	e->pid = pid;
	e->dfd = -100; // AT_FDCWD
	e->dfd2 = -100;
	e->flags = 0;
	e->path_len = 0;
	e->path2_len = 0;
	e->pad = 0;
	e->path[0] = 0; // never leak the previous event's path on this CPU
	e->path2[0] = 0;
	e->args[0] = 0;
	e->args[1] = 0;
	e->args[2] = 0;
	e->args[3] = 0;
	if (nargs > 0)
		e->args[0] = ctx->args[0];
	if (nargs > 1)
		e->args[1] = ctx->args[1];
	if (nargs > 2)
		e->args[2] = ctx->args[2];
	if (nargs > 3)
		e->args[3] = ctx->args[3];
	return e;
}

// handle_path covers every syscall that names a filesystem object.
// path_idx/path2_idx/dfd_idx/dfd2_idx/flags_idx are syscall argument slots
// (-1 = not applicable). They are compile-time constants at every call site.
static __always_inline int handle_path(struct trace_event_raw_sys_enter *ctx, __u32 op,
				       int path_idx, int path2_idx, int dfd_idx, int dfd2_idx,
				       int flags_idx)
{
	int v1 = head_verdict((const char *)sys_arg(ctx, path_idx));
	int v2 = 0;
	if (path2_idx >= 0)
		v2 = head_verdict((const char *)sys_arg(ctx, path2_idx));
	if (!v1 && !v2)
		return 0;

	struct audit_event *e = begin(ctx, op, 0);
	if (!e)
		return 0;

	int ret = bpf_probe_read_user_str(e->path, sizeof(e->path),
					  (const char *)sys_arg(ctx, path_idx));
	if (ret > 0)
		e->path_len = ret;
	if (path2_idx >= 0) {
		ret = bpf_probe_read_user_str(e->path2, sizeof(e->path2),
					      (const char *)sys_arg(ctx, path2_idx));
		if (ret > 0)
			e->path2_len = ret;
	}

	int keep = (v1 == 1) || (v2 == 1) ||
		   (v1 == 2 && has_hidden_component(e->path)) ||
		   (v2 == 2 && has_hidden_component(e->path2));
	if (!keep)
		return 0;

	if (dfd_idx >= 0)
		e->dfd = (int)sys_arg(ctx, dfd_idx);
	if (dfd2_idx >= 0)
		e->dfd2 = (int)sys_arg(ctx, dfd2_idx);
	if (flags_idx >= 0)
		e->flags = (__u32)sys_arg(ctx, flags_idx);

	fill_task(e);
	return submit(e);
}

#define PATH_PROG(sc, op, p, p2, d, d2, f)                                              \
	SEC("tracepoint/syscalls/sys_enter_" #sc)                                           \
	int audit_##sc(struct trace_event_raw_sys_enter *ctx)                               \
	{                                                                                   \
		return handle_path(ctx, op, p, p2, d, d2, f);                                   \
	}

//        syscall     op            path path2 dfd dfd2 flags
PATH_PROG(open,       AOP_OPEN,        0,  -1,  -1, -1,  1)
PATH_PROG(openat,     AOP_OPENAT,      1,  -1,   0, -1,  2)
PATH_PROG(creat,      AOP_CREAT,       0,  -1,  -1, -1, -1)
PATH_PROG(truncate,   AOP_TRUNCATE,    0,  -1,  -1, -1, -1)
PATH_PROG(mkdir,      AOP_MKDIR,       0,  -1,  -1, -1, -1)
PATH_PROG(mkdirat,    AOP_MKDIRAT,     1,  -1,   0, -1, -1)
PATH_PROG(rmdir,      AOP_RMDIR,       0,  -1,  -1, -1, -1)
PATH_PROG(unlink,     AOP_UNLINK,      0,  -1,  -1, -1, -1)
PATH_PROG(unlinkat,   AOP_UNLINKAT,    1,  -1,   0, -1,  2)
PATH_PROG(rename,     AOP_RENAME,      0,   1,  -1, -1, -1)
PATH_PROG(renameat,   AOP_RENAMEAT,    1,   3,   0,  2, -1)
PATH_PROG(renameat2,  AOP_RENAMEAT2,   1,   3,   0,  2, -1)
PATH_PROG(link,       AOP_LINK,        0,   1,  -1, -1, -1)
PATH_PROG(linkat,     AOP_LINKAT,      1,   3,   0,  2, -1)
PATH_PROG(symlink,    AOP_SYMLINK,     1,  -1,  -1, -1, -1)
PATH_PROG(symlinkat,  AOP_SYMLINKAT,   2,  -1,   1, -1, -1)
PATH_PROG(chmod,      AOP_CHMOD,       0,  -1,  -1, -1, -1)
PATH_PROG(fchmodat,   AOP_FCHMODAT,    1,  -1,   0, -1, -1)
PATH_PROG(fchmodat2,  AOP_FCHMODAT2,   1,  -1,   0, -1, -1)
PATH_PROG(chown,      AOP_CHOWN,       0,  -1,  -1, -1, -1)
PATH_PROG(lchown,     AOP_LCHOWN,      0,  -1,  -1, -1, -1)
PATH_PROG(fchownat,   AOP_FCHOWNAT,    1,  -1,   0, -1, -1)
PATH_PROG(utimensat,  AOP_UTIMENSAT,   1,  -1,   0, -1, -1)
PATH_PROG(mknod,      AOP_MKNOD,       0,  -1,  -1, -1, -1)
PATH_PROG(mknodat,    AOP_MKNODAT,     1,  -1,   0, -1, -1)

// openat2 carries its flags in struct open_how (first u64).
SEC("tracepoint/syscalls/sys_enter_openat2")
int audit_openat2(struct trace_event_raw_sys_enter *ctx)
{
	int v = head_verdict((const char *)ctx->args[1]);
	if (!v)
		return 0;
	struct audit_event *e = begin(ctx, AOP_OPENAT2, 0);
	if (!e)
		return 0;

	int ret = bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)ctx->args[1]);
	if (ret > 0)
		e->path_len = ret;
	if (v == 2 && !has_hidden_component(e->path))
		return 0;

	__u64 how_flags = 0;
	bpf_probe_read_user(&how_flags, sizeof(how_flags), (const void *)ctx->args[2]);
	e->dfd = (int)ctx->args[0];
	e->flags = (__u32)how_flags;

	fill_task(e);
	return submit(e);
}

// handle_plain covers syscalls that are reported unconditionally and whose
// interesting data is only the raw numeric arguments.
static __always_inline int handle_plain(struct trace_event_raw_sys_enter *ctx, __u32 op,
					int name_idx, int nargs)
{
	struct audit_event *e = begin(ctx, op, nargs);
	if (!e)
		return 0;

	if (name_idx >= 0) {
		int ret = bpf_probe_read_user_str(e->path, sizeof(e->path),
						  (const char *)sys_arg(ctx, name_idx));
		if (ret > 0)
			e->path_len = ret;
	}
	fill_task(e);
	return submit(e);
}

#define PLAIN_PROG(sc, op, name_idx, nargs)                                                    \
	SEC("tracepoint/syscalls/sys_enter_" #sc)                                           \
	int audit_##sc(struct trace_event_raw_sys_enter *ctx)                               \
	{                                                                                   \
		return handle_plain(ctx, op, name_idx, nargs);                                         \
	}

PLAIN_PROG(sysinfo,       AOP_SYSINFO,       -1, 1)
PLAIN_PROG(syslog,        AOP_SYSLOG,        -1, 3)
PLAIN_PROG(personality,   AOP_PERSONALITY,   -1, 1)
PLAIN_PROG(memfd_create,  AOP_MEMFD_CREATE,   0, 2)
PLAIN_PROG(init_module,   AOP_INIT_MODULE,   -1, 3)
PLAIN_PROG(finit_module,  AOP_FINIT_MODULE,  -1, 3)
PLAIN_PROG(delete_module, AOP_DELETE_MODULE,  0, 2)

// connect(2): report AF_INET / AF_INET6 destinations (auditd rule
// "-S connect -F a2=16/28"). The raw sockaddr is copied to e->path.
SEC("tracepoint/syscalls/sys_enter_connect")
int audit_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct audit_event *e = begin(ctx, AOP_CONNECT, 3);
	if (!e)
		return 0;

	const void *uaddr = (const void *)ctx->args[1];
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), uaddr) != 0)
		return 0;

	if (family == AF_INET) {
		if (bpf_probe_read_user(e->path, 16, uaddr) != 0)
			return 0;
		e->path_len = 16;
	} else if (family == AF_INET6) {
		// 24 bytes is all the kernel requires (sin6_scope_id is optional)
		if (bpf_probe_read_user(e->path, 24, uaddr) != 0)
			return 0;
		e->path_len = 24;
	} else {
		return 0;
	}

	fill_task(e);
	return submit(e);
}

char LICENSE[] SEC("license") = "GPL";
