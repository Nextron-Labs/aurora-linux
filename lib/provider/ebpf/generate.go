package ebpf

// These go:generate directives produce the Go types and compiled BPF ELF objects
// from the BPF C source files. Run on a Linux system with clang and bpftool installed:
//
//   go generate ./lib/provider/ebpf/
//
// The generated files (*_bpfel.go and *_bpfel.o) are checked into the repo
// so that `go build` works without clang installed.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang execMonitor bpf/exec_monitor.c -- -I/usr/include -I./bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang fileMonitor bpf/file_monitor.c -- -I/usr/include -I./bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang netMonitor bpf/net_monitor.c -- -I/usr/include -I./bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpfMonitor bpf/bpf_monitor.c -- -I/usr/include -I./bpf/headers
