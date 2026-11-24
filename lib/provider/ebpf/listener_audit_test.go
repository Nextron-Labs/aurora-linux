package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func fentry(target string) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: target}
}

func withKernelFuncs(t *testing.T, lookup func() (func(string) bool, error)) {
	t.Helper()
	orig := kernelFuncLookup
	kernelFuncLookup = lookup
	t.Cleanup(func() { kernelFuncLookup = orig })
}

func TestPruneMissingAttachTargetsDropsOnlyMissingHooks(t *testing.T) {
	// Kernel built without CONFIG_SECURITY_PATH: security_path_* is absent.
	withKernelFuncs(t, func() (func(string) bool, error) {
		have := map[string]bool{"security_file_open": true, "security_inode_setattr": true}
		return func(name string) bool { return have[name] }, nil
	})
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"hook_file_open":     fentry("security_file_open"),
		"hook_inode_setattr": fentry("security_inode_setattr"),
		"hook_path_mknod":    fentry("security_path_mknod"),
		"hook_path_unlink":   fentry("security_path_unlink"),
		"audit_openat":       {Type: ebpf.TracePoint, SectionName: "tracepoint/syscalls/sys_enter_openat"},
	}}

	pruneMissingAttachTargets(spec, "audit_hooks")

	for _, gone := range []string{"hook_path_mknod", "hook_path_unlink"} {
		if _, ok := spec.Programs[gone]; ok {
			t.Errorf("%s should have been pruned (target missing)", gone)
		}
	}
	for _, kept := range []string{"hook_file_open", "hook_inode_setattr", "audit_openat"} {
		if _, ok := spec.Programs[kept]; !ok {
			t.Errorf("%s should have been kept", kept)
		}
	}
}

func TestPruneMissingAttachTargetsKeepsAllWithoutKernelBTF(t *testing.T) {
	withKernelFuncs(t, func() (func(string) bool, error) {
		return nil, errors.New("no /sys/kernel/btf/vmlinux")
	})
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"hook_file_open":  fentry("security_file_open"),
		"hook_path_mknod": fentry("security_path_mknod"),
	}}

	pruneMissingAttachTargets(spec, "audit_hooks")

	if len(spec.Programs) != 2 {
		t.Fatalf("without kernel BTF nothing may be pruned, got %d programs", len(spec.Programs))
	}
}

func TestPruneMissingAttachTargetsSkipsBTFWithoutTracingPrograms(t *testing.T) {
	withKernelFuncs(t, func() (func(string) bool, error) {
		t.Fatal("kernel BTF must not be read when no program needs an attach target")
		return nil, nil
	})
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"audit_openat": {Type: ebpf.TracePoint, SectionName: "tracepoint/syscalls/sys_enter_openat"},
	}}

	pruneMissingAttachTargets(spec, "audit_monitor")

	if len(spec.Programs) != 1 {
		t.Fatalf("tracepoint program was pruned")
	}
}
