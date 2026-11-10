// SPDX-License-Identifier: GPL-2.0
// audit_hooks.c — fentry programs on LSM security hooks producing the
// auditd-compatible PATH/SYSCALL records.
//
// Why security hooks instead of sys_enter tracepoints:
//   * the kernel has already resolved the object: paths are canonical and
//     cannot be respelled ("//etc", "/./", "..", symlinks, /proc/self/fd),
//     raced from another thread, or hidden in unpaged user memory;
//   * every entry point reaches them: compat (32-bit) syscalls, io_uring,
//     open_by_handle_at, fd-based calls;
//   * they run after permission checks, so denied attempts by unprivileged
//     users do not produce noise.
//
// Matching is inode based, like auditd's "-w" watches: userland registers
// the inodes of watched files and of the directories in which watched files
// can be created. A second, name-based check (leaf name) catches writes and
// creations in other mount namespaces (containers) whose inodes are unknown.
// The full path is only built on a hit.
//
// Operation codes MUST match hookOp* in audit_hooks.go.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aurora_path.h"

#include "aurora_hooks.h"

#define NAME_KEY 32

struct inode_key {
	__u64 ino;
	__u32 dev; // kernel dev_t (MAJOR<<20 | MINOR), as in /proc/self/mountinfo
	__u32 pad;
};

struct watch_val {
	__u32 id;
	__u8  flags; // W_*
	__u8  perms; // PERM_*
	__u16 pad;
};

struct name_key {
	char name[NAME_KEY];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, struct inode_key);
	__type(value, struct watch_val);
} watch_inodes SEC(".maps");

// Leaf names of exactly-named watched files (e.g. "ld.so.preload").
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct name_key);
	__type(value, __u8);
} watch_names SEC(".maps");

static __always_inline struct watch_val *lookup_inode(struct inode *inode)
{
	if (!inode)
		return NULL;
	struct inode_key k = {};
	k.ino = BPF_CORE_READ(inode, i_ino);
	k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	return bpf_map_lookup_elem(&watch_inodes, &k);
}

static __always_inline struct watch_val *lookup_dentry_inode(struct dentry *d)
{
	if (!d)
		return NULL;
	return lookup_inode(BPF_CORE_READ(d, d_inode));
}

static __always_inline int name_watched(struct dentry *d)
{
	if (!d)
		return 0;
	struct name_key k = {};
	__u32 len;
	const unsigned char *name;
	ap_dname(d, &len, &name);
	if (bpf_probe_read_kernel_str(k.name, sizeof(k.name), name) <= 1)
		return 0;
	return bpf_map_lookup_elem(&watch_names, &k) != NULL;
}

static __always_inline void set_path(struct hook_event *e, const struct path *p, struct dentry *extra)
{
	struct vfsmount *mnt = BPF_CORE_READ(p, mnt);
	struct dentry *d = BPF_CORE_READ(p, dentry);
	__u32 complete = 0;
	e->path_len = ap_resolve(mnt, d, extra, e->path, HOOK_PATH, &complete);
	if (!complete)
		e->flags |= HOOK_F_PATH1_PARTIAL;
}

static __always_inline void set_path2(struct hook_event *e, const struct path *p, struct dentry *extra)
{
	struct vfsmount *mnt = BPF_CORE_READ(p, mnt);
	struct dentry *d = BPF_CORE_READ(p, dentry);
	__u32 complete = 0;
	e->path2_len = ap_resolve(mnt, d, extra, e->path2, HOOK_PATH, &complete);
	if (!complete)
		e->flags |= HOOK_F_PATH2_PARTIAL;
}

// ---------------------------------------------------------------------------
// open: the hot path. One hash lookup for every open on the system; the leaf
// name is only looked at for writes.
// ---------------------------------------------------------------------------

SEC("fentry/security_file_open")
int BPF_PROG(hook_file_open, struct file *file)
{
	__u32 fmode = BPF_CORE_READ(file, f_mode);
	__u32 access = 0;
	if (fmode & FMODE_READ)
		access |= PERM_R;
	if ((fmode & FMODE_WRITE) || (BPF_CORE_READ(file, f_flags) & O_TRUNC))
		access |= PERM_W;

	struct watch_val *w = lookup_inode(BPF_CORE_READ(file, f_inode));
	int hit = w && (w->flags & W_FILE) && (w->perms & access);
	if (!hit && (access & PERM_W))
		hit = name_watched(BPF_CORE_READ(file, f_path.dentry));
	if (!hit || is_self())
		return 0;

	struct hook_event *e = begin(HOP_OPEN);
	if (!e)
		return 0;
	if (w)
		e->watch_id = w->id;
	e->access = access;
	set_path(e, &file->f_path, NULL);
	return submit(e);
}

SEC("fentry/security_file_truncate")
int BPF_PROG(hook_file_truncate, struct file *file)
{
	struct watch_val *w = lookup_inode(BPF_CORE_READ(file, f_inode));
	int hit = w && (w->flags & W_FILE) && (w->perms & PERM_W);
	if (!hit)
		hit = name_watched(BPF_CORE_READ(file, f_path.dentry));
	if (!hit || is_self())
		return 0;
	struct hook_event *e = begin(HOP_TRUNCATE);
	if (!e)
		return 0;
	if (w)
		e->watch_id = w->id;
	e->access = PERM_W;
	set_path(e, &file->f_path, NULL);
	return submit(e);
}

extern int LINUX_KERNEL_VERSION __kconfig;

// chmod/chown/utimes/truncate on a path or fd all end here. Since 5.12 the
// first argument is the mount's user namespace / idmap and the dentry second.
SEC("fentry/security_inode_setattr")
int hook_inode_setattr(unsigned long long *ctx)
{
	struct dentry *dentry;
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 12, 0))
		dentry = (struct dentry *)ctx[1];
	else
		dentry = (struct dentry *)ctx[0];

	struct watch_val *w = lookup_dentry_inode(dentry);
	if (!(w && (w->flags & W_FILE) && (w->perms & PERM_A)))
		return 0;
	if (is_self())
		return 0;
	struct hook_event *e = begin(HOP_SETATTR);
	if (!e)
		return 0;
	e->watch_id = w->id;
	e->access = PERM_A;
	// Only inode hits reach here: userland names the record after the watch
	// entry, so no path walk is needed (and there is no vfsmount anyway).
	return submit(e);
}

// ---------------------------------------------------------------------------
// namespace changes: creation, removal, rename, links
// ---------------------------------------------------------------------------

// dir_hit: the directory in which an entry is created/removed is watched,
// either directly or through a recursive watch on one of its ancestors
// (e.g. "mkdir -p /etc/systemd/system && cp x.service ..." under a watch on
// the nearest existing ancestor). Only used by the (rare) namespace hooks.
static __always_inline int dir_hit(const struct path *dir, struct watch_val **out)
{
	struct dentry *d = BPF_CORE_READ(dir, dentry);
	struct watch_val *w = lookup_dentry_inode(d);
	if (w && (w->flags & W_DIR)) {
		*out = w;
		return 1;
	}
#pragma unroll
	for (int i = 0; i < RECURSIVE_DEPTH; i++) {
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (!parent || parent == d)
			return 0;
		d = parent;
		w = lookup_dentry_inode(d);
		if (w && (w->flags & W_RECURSIVE)) {
			*out = w;
			return 1;
		}
	}
	return 0;
}

SEC("fentry/security_path_mknod")
int BPF_PROG(hook_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
	struct watch_val *w = NULL;
	// mknod(2)-style special files: character/block devices and FIFOs.
	// Sockets also pass here (bind() of a unix socket) and are not mknod.
	__u32 fmt = mode & S_IFMT;
	int special = fmt == S_IFCHR || fmt == S_IFBLK || fmt == S_IFIFO;
	int hit = dir_hit(dir, &w) || name_watched(dentry);
	if ((!hit && !special) || is_self())
		return 0;
	struct hook_event *e = begin(special ? HOP_MKNOD_SPECIAL : HOP_CREATE);
	if (!e)
		return 0;
	if (w)
		e->watch_id = w->id;
	e->mode = mode;
	set_path(e, dir, dentry);
	return submit(e);
}

SEC("fentry/security_path_mkdir")
int BPF_PROG(hook_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	struct watch_val *w = NULL;
	if (!dir_hit(dir, &w) || is_self())
		return 0;
	struct hook_event *e = begin(HOP_MKDIR);
	if (!e)
		return 0;
	e->watch_id = w->id;
	e->mode = mode;
	set_path(e, dir, dentry);
	return submit(e);
}

static __always_inline int removal(__u32 op, const struct path *dir, struct dentry *dentry)
{
	struct watch_val *w = NULL;
	struct watch_val *f = lookup_dentry_inode(dentry);
	int hit = (f && (f->flags & (W_FILE | W_DIR))) || dir_hit(dir, &w) || name_watched(dentry);
	if (!hit || is_self())
		return 0;
	struct hook_event *e = begin(op);
	if (!e)
		return 0;
	if (f)
		e->watch_id = f->id;
	else if (w)
		e->watch_id = w->id;
	set_path(e, dir, dentry);
	return submit(e);
}

SEC("fentry/security_path_unlink")
int BPF_PROG(hook_path_unlink, const struct path *dir, struct dentry *dentry)
{
	return removal(HOP_UNLINK, dir, dentry);
}

SEC("fentry/security_path_rmdir")
int BPF_PROG(hook_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	return removal(HOP_RMDIR, dir, dentry);
}

SEC("fentry/security_path_rename")
int BPF_PROG(hook_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry)
{
	struct watch_val *w1 = NULL, *w2 = NULL;
	struct watch_val *src = lookup_dentry_inode(old_dentry);
	struct watch_val *dst = lookup_dentry_inode(new_dentry); // replaced target, if any
	int hit = (src && (src->flags & (W_FILE | W_DIR))) || (dst && (dst->flags & W_FILE)) ||
		  dir_hit(old_dir, &w1) || dir_hit(new_dir, &w2) ||
		  name_watched(old_dentry) || name_watched(new_dentry);
	if (!hit || is_self())
		return 0;
	struct hook_event *e = begin(HOP_RENAME);
	if (!e)
		return 0;
	if (src)
		e->watch_id = src->id;
	else if (w1)
		e->watch_id = w1->id;
	if (dst)
		e->watch_id2 = dst->id;
	else if (w2)
		e->watch_id2 = w2->id;
	set_path(e, old_dir, old_dentry);
	set_path2(e, new_dir, new_dentry);
	return submit(e);
}

SEC("fentry/security_path_link")
int BPF_PROG(hook_path_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	struct watch_val *w = NULL;
	struct watch_val *src = lookup_dentry_inode(old_dentry);
	int hit = (src && (src->flags & W_FILE)) || dir_hit(new_dir, &w) || name_watched(new_dentry);
	if (!hit || is_self())
		return 0;
	struct hook_event *e = begin(HOP_LINK);
	if (!e)
		return 0;
	if (src)
		e->watch_id = src->id;
	if (w)
		e->watch_id2 = w->id;
	// Hard links never cross mounts: the source lives on new_dir's mount.
	__u32 complete = 0;
	e->path_len = ap_resolve(BPF_CORE_READ(new_dir, mnt), old_dentry, NULL, e->path, HOOK_PATH, &complete);
	if (!complete)
		e->flags |= HOOK_F_PATH1_PARTIAL;
	set_path2(e, new_dir, new_dentry);
	return submit(e);
}

SEC("fentry/security_path_symlink")
int BPF_PROG(hook_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	struct watch_val *w = NULL;
	if (!(dir_hit(dir, &w) || name_watched(dentry)) || is_self())
		return 0;
	struct hook_event *e = begin(HOP_SYMLINK);
	if (!e)
		return 0;
	if (w)
		e->watch_id = w->id;
	set_path(e, dir, dentry);
	// symlink target text (kernel copy)
	int n = bpf_probe_read_kernel_str(e->path2, sizeof(e->path2), old_name);
	if (n > 0)
		e->path2_len = n;
	return submit(e);
}

// ---------------------------------------------------------------------------
// non-file records
// ---------------------------------------------------------------------------

SEC("fentry/security_socket_connect")
int BPF_PROG(hook_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u16 family = BPF_CORE_READ(address, sa_family);
	__u32 n;
	if (family == AF_INET)
		n = 16;
	else if (family == AF_INET6)
		n = 24;
	else
		return 0;
	if (addrlen < (int)n || is_self())
		return 0;
	struct hook_event *e = begin(HOP_CONNECT);
	if (!e)
		return 0;
	// kernel copy of the sockaddr: no user-space race
	if (bpf_probe_read_kernel(e->path, n & 31, address) != 0)
		return 0;
	e->path_len = n;
	return submit(e);
}

SEC("fentry/security_syslog")
int BPF_PROG(hook_syslog, int type)
{
	if (is_self())
		return 0;
	struct hook_event *e = begin(HOP_SYSLOG);
	if (!e)
		return 0;
	e->access = type;
	return submit(e);
}

SEC("fentry/security_kernel_load_data")
int BPF_PROG(hook_kernel_load_data, enum kernel_load_data_id id, bool contents)
{
	if (id != bpf_core_enum_value(enum kernel_load_data_id, LOADING_MODULE) || is_self())
		return 0;
	struct hook_event *e = begin(HOP_INIT_MODULE);
	if (!e)
		return 0;
	return submit(e);
}

SEC("fentry/security_kernel_read_file")
int BPF_PROG(hook_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	if (id != bpf_core_enum_value(enum kernel_read_file_id, READING_MODULE) || is_self())
		return 0;
	struct hook_event *e = begin(HOP_FINIT_MODULE);
	if (!e)
		return 0;
	set_path(e, &file->f_path, NULL);
	return submit(e);
}

char LICENSE[] SEC("license") = "GPL";
