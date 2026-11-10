//go:build !linux

package ebpf

// HardenSelf is a no-op outside Linux.
func HardenSelf() []error { return nil }
