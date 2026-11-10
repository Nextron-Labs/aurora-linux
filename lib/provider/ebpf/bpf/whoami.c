// SPDX-License-Identifier: GPL-2.0
// whoami.c — learns Aurora's pid as the kernel sees it (root pid namespace).
// Aurora calls getpgid(magic); this program stores the caller's tgid. Every
// BPF self-exclusion/protection map is keyed by that value, which differs
// from os.Getpid() when Aurora runs inside a pid namespace (container).

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} whoami SEC(".maps"); // [0] = magic (set by userland), [1] = answer

SEC("tracepoint/syscalls/sys_enter_getpgid")
int whoami_getpgid(struct trace_event_raw_sys_enter *ctx)
{
	__u32 k0 = 0, k1 = 1;
	__u64 *magic = bpf_map_lookup_elem(&whoami, &k0);
	if (!magic || *magic == 0 || (__u64)ctx->args[0] != *magic)
		return 0;
	__u64 me = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&whoami, &k1, &me, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
