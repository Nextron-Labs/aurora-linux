//go:build !linux

package ebpf

type syscallStatfs struct{}

func statfsIsBPF(string, *syscallStatfs) bool { return false }
