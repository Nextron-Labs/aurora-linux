// SPDX-License-Identifier: GPL-2.0
// aurora_path.h — in-kernel path resolution shared by the security-hook
// programs.
//
// Paths are rebuilt from the kernel's own dentry/mount objects, so they are
// canonical (no "//", "/./", "..", symlinks or /proc/self/fd aliases) and
// cannot be raced by user space. The walk is bounded and only performed on
// watch hits, never on the hot path.

#ifndef AURORA_PATH_H
#define AURORA_PATH_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define AP_MAX_COMPONENTS 40
#define AP_NAME_MAX       255
#define AP_HALF           4096 // working area; the buffer is twice as large
#define AP_MASK           (AP_HALF - 1)

struct ap_buf {
	char b[AP_HALF * 2];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ap_buf);
} ap_scratch SEC(".maps");

static __always_inline struct mount *ap_real_mount(struct vfsmount *mnt)
{
	return (struct mount *)((void *)mnt - bpf_core_field_offset(struct mount, mnt));
}

// Since 6.8 dentry::d_name is a const alias of __d_name inside an anonymous
// union; CO-RE resolves the non-const member reliably, older kernels only
// have d_name.
struct dentry___old {
	struct qstr d_name;
} __attribute__((preserve_access_index));

static __always_inline void ap_dname(struct dentry *d, __u32 *len, const unsigned char **name)
{
	if (bpf_core_field_exists(d->__d_name)) {
		*len = BPF_CORE_READ(d, __d_name.len);
		*name = BPF_CORE_READ(d, __d_name.name);
	} else {
		struct dentry___old *o = (void *)d;
		*len = BPF_CORE_READ(o, d_name.len);
		*name = BPF_CORE_READ(o, d_name.name);
	}
}

struct ap_ctx {
	struct mount  *mnt;
	struct dentry *mnt_root;
	struct dentry *d;
	struct dentry *dentry; // continuation after the extra component
	struct ap_buf *buf;
	__u32 pos;
	__u32 extra_pending;
	__u32 done; // reached the root (path is complete)
};

// One component per call. The default build drives it with bpf_loop, which
// keeps verification cost independent of the number of iterations (kernel
// 5.17+). The AURORA_LEGACY build (older kernels) unrolls AP_LEGACY_STEPS
// calls instead; deeper paths are reported as partial.
#ifdef AURORA_LEGACY
#define AP_LEGACY_STEPS 8
static __always_inline long ap_step(__u32 i, void *data)
#else
static long ap_step(__u32 i, void *data)
#endif
{
	struct ap_ctx *c = data;
	struct ap_buf *buf = c->buf;
	if (!buf)
		return 1;

	struct dentry *d = c->d;
	if (!c->extra_pending) {
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		// Copy to locals: BPF_CORE_READ(c->mnt, ...) would root the CO-RE
		// relocation at struct ap_ctx, which the kernel does not know.
		struct mount *mnt = c->mnt;
		if (mnt && d == c->mnt_root) {
			struct mount *mparent = BPF_CORE_READ(mnt, mnt_parent);
			if (mparent == mnt) {
				c->done = 1;
				return 1; // root of the mount namespace
			}
			c->d = BPF_CORE_READ(mnt, mnt_mountpoint);
			c->mnt = mparent;
			c->mnt_root = BPF_CORE_READ(mparent, mnt.mnt_root);
			return 0;
		}
		if (d == parent) {
			c->done = 1;
			return 1; // filesystem root
		}
	}

	__u32 len;
	const unsigned char *name;
	ap_dname(d, &len, &name);
	if (len == 0 || len > AP_NAME_MAX || c->pos < len + 1)
		return 1;
	c->pos -= len;
	__u64 sz = len;
	__u64 off = c->pos;
	barrier_var(sz);
	barrier_var(off);
	sz &= AP_NAME_MAX;
	off &= AP_MASK;
	if (bpf_probe_read_kernel(&buf->b[off], sz, name) != 0)
		return 1;
	c->pos -= 1;
	buf->b[c->pos & AP_MASK] = '/';

	if (c->extra_pending) {
		c->extra_pending = 0;
		c->d = c->dentry;
		return 0;
	}
	c->d = BPF_CORE_READ(d, d_parent);
	return 0;
}

// ap_resolve writes the absolute path of (mnt, dentry) into out (NUL
// terminated) and returns its length including the NUL, or 0 on failure.
// If mnt is NULL the walk stops at the root of the dentry's filesystem.
// extra, if non-NULL, is appended as a final component (hooks that pass a
// parent directory plus a not-yet-instantiated dentry).
// out_size must be a compile-time power of two (used as a verifier mask).
// Over-long paths keep their leading components.
// *complete (if non-NULL) is set when the walk reached the root.
static __always_inline __u32 ap_resolve(struct vfsmount *vfsmnt, struct dentry *dentry,
					struct dentry *extra, char *out, __u32 out_size, __u32 *complete)
{
	__u32 zero = 0;
	struct ap_buf *buf = bpf_map_lookup_elem(&ap_scratch, &zero);
	if (!buf)
		return 0;
	buf->b[AP_HALF - 1] = 0;

	struct ap_ctx c = {};
	c.buf = buf;
	c.pos = AP_HALF - 1;
	c.mnt = vfsmnt ? ap_real_mount(vfsmnt) : NULL;
	c.mnt_root = vfsmnt ? BPF_CORE_READ(vfsmnt, mnt_root) : NULL;
	c.d = extra ? extra : dentry;
	c.dentry = dentry;
	c.extra_pending = extra != NULL;
#ifdef AURORA_LEGACY
#pragma unroll
	for (int i = 0; i < AP_LEGACY_STEPS; i++) {
		if (ap_step(i, &c))
			break;
	}
#else
	bpf_loop(AP_MAX_COMPONENTS, ap_step, &c, 0);
#endif
	if (complete)
		*complete = c.done;

	__u32 pos = c.pos;
	if (pos > AP_HALF - 1)
		return 0;
	if (pos == AP_HALF - 1) { // the root itself
		pos -= 1;
		buf->b[pos & AP_MASK] = '/';
	}

	__u32 n = AP_HALF - 1 - pos; // length without the NUL
	if (n > out_size - 1)
		n = out_size - 1;
	if (n == 0)
		return 0;
	__u64 sz = n;
	__u64 off = pos;
	barrier_var(sz);
	barrier_var(off);
	sz &= (out_size - 1);
	off &= AP_MASK;
	if (bpf_probe_read_kernel(out, sz, &buf->b[off]) != 0)
		return 0;
	out[sz] = 0;
	return sz + 1;
}

#endif
