# Vendored libbpf headers

`bpf/` holds the BPF-side headers from libbpf 1.3.0 (`bpf_helpers.h`,
`bpf_helper_defs.h`, `bpf_core_read.h`, `bpf_tracing.h`), copied from Ubuntu
24.04's `libbpf-dev` 1:1.3.0-2build2. They are dual-licensed
LGPL-2.1 OR BSD-2-Clause, as stated in each file.

`generate.go` puts this directory ahead of `/usr/include`, so the BPF programs
build the same way regardless of the host's libbpf. Distribution packages on
older systems are too old: Ubuntu 22.04 ships libbpf 0.5, which lacks
`bpf_core_field_offset(type, field)`, `barrier_var` and the `bpf_loop` helper.

These headers only affect compilation. Which features the programs use at run
time is decided by the loader's kernel checks and the `AURORA_LEGACY` builds.
