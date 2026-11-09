// SPDX-License-Identifier: GPL-2.0
// syscall_hooks.c — sysinfo, personality, memfd_create and delete_module have
// no LSM hook. The generic sys_enter tracepoints do not fire for 32-bit
// (compat) callers, so these fentry programs attach to the per-ABI syscall
// entry functions instead: the 64-bit ones and the compat ones. Arguments
// come from the saved user registers of the respective ABI.
//
// Built per architecture (bpf2go -target amd64,arm64). Events go to the
// hook_events ring buffer of audit_hooks.c (map replacement at load time).

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aurora_hooks.h"

static __always_inline int emit_sysinfo(int compat)
{
	if (is_self())
		return 0;
	struct hook_event *e = begin(HOP_SYSINFO);
	if (!e)
		return 0;
	if (compat)
		e->flags |= HOOK_F_COMPAT;
	return submit(e);
}

static __always_inline int emit_personality(__u64 persona, int compat)
{
	if (is_self())
		return 0;
	struct hook_event *e = begin(HOP_PERSONALITY);
	if (!e)
		return 0;
	e->access = (__u32)persona;
	if (compat)
		e->flags |= HOOK_F_COMPAT;
	return submit(e);
}

static __always_inline int emit_named(__u32 op, __u64 uname, __u64 flags, int compat)
{
	if (is_self())
		return 0;
	struct hook_event *e = begin(op);
	if (!e)
		return 0;
	int n = bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)uname);
	if (n > 0)
		e->path_len = n;
	e->mode = (__u32)flags;
	if (compat)
		e->flags |= HOOK_F_COMPAT;
	return submit(e);
}

#if defined(__TARGET_ARCH_x86)
// 64-bit ABI: rdi, rsi, rdx ...; i386 ABI: ebx, ecx, edx ...
#define A0_64(r) BPF_CORE_READ(r, di)
#define A1_64(r) BPF_CORE_READ(r, si)
#define A0_32(r) ((__u32)BPF_CORE_READ(r, bx))
#define A1_32(r) ((__u32)BPF_CORE_READ(r, cx))

SEC("fentry/__x64_sys_sysinfo")
int BPF_PROG(sc_sysinfo64, const struct pt_regs *regs) { return emit_sysinfo(0); }
SEC("fentry/__ia32_compat_sys_sysinfo")
int BPF_PROG(sc_sysinfo32, const struct pt_regs *regs) { return emit_sysinfo(1); }

SEC("fentry/__x64_sys_personality")
int BPF_PROG(sc_personality64, const struct pt_regs *regs) { return emit_personality(A0_64(regs), 0); }
SEC("fentry/__ia32_sys_personality")
int BPF_PROG(sc_personality32, const struct pt_regs *regs) { return emit_personality(A0_32(regs), 1); }

SEC("fentry/__x64_sys_memfd_create")
int BPF_PROG(sc_memfd64, const struct pt_regs *regs) { return emit_named(HOP_MEMFD_CREATE, A0_64(regs), A1_64(regs), 0); }
SEC("fentry/__ia32_sys_memfd_create")
int BPF_PROG(sc_memfd32, const struct pt_regs *regs) { return emit_named(HOP_MEMFD_CREATE, A0_32(regs), A1_32(regs), 1); }

SEC("fentry/__x64_sys_delete_module")
int BPF_PROG(sc_delmod64, const struct pt_regs *regs) { return emit_named(HOP_DELETE_MODULE, A0_64(regs), A1_64(regs), 0); }
SEC("fentry/__ia32_sys_delete_module")
int BPF_PROG(sc_delmod32, const struct pt_regs *regs) { return emit_named(HOP_DELETE_MODULE, A0_32(regs), A1_32(regs), 1); }

#elif defined(__TARGET_ARCH_arm64)
// AArch64 and AArch32 (compat) both pass arguments in regs[0..]. vmlinux.h
// comes from the build host (x86), so declare the arm64 layout as a CO-RE
// flavor; it is relocated against the arm64 kernel's BTF at load time.
struct pt_regs___aurora_arm64 {
	__u64 regs[31];
} __attribute__((preserve_access_index));
#define A0(r) BPF_CORE_READ((const struct pt_regs___aurora_arm64 *)(r), regs[0])
#define A1(r) BPF_CORE_READ((const struct pt_regs___aurora_arm64 *)(r), regs[1])

SEC("fentry/__arm64_sys_sysinfo")
int BPF_PROG(sc_sysinfo64, const struct pt_regs *regs) { return emit_sysinfo(0); }
SEC("fentry/__arm64_compat_sys_sysinfo")
int BPF_PROG(sc_sysinfo32, const struct pt_regs *regs) { return emit_sysinfo(1); }

// The compat tables use the native entry points for these.
SEC("fentry/__arm64_sys_personality")
int BPF_PROG(sc_personality64, const struct pt_regs *regs) { return emit_personality(A0(regs), 0); }
SEC("fentry/__arm64_sys_memfd_create")
int BPF_PROG(sc_memfd64, const struct pt_regs *regs) { return emit_named(HOP_MEMFD_CREATE, A0(regs), A1(regs), 0); }
SEC("fentry/__arm64_sys_delete_module")
int BPF_PROG(sc_delmod64, const struct pt_regs *regs) { return emit_named(HOP_DELETE_MODULE, A0(regs), A1(regs), 0); }
#endif

char LICENSE[] SEC("license") = "GPL";
