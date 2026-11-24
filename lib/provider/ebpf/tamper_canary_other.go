//go:build !linux

package ebpf

import "os/exec"

func canaryActions(string) {}

// setPdeathsig is Linux-only (no parent-death signal elsewhere).
func setPdeathsig(*exec.Cmd) {}
