SHELL := /bin/bash

GO ?= go
VERSION ?= 0.2.0
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
HOST_OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
BPF_HEADERS_DIR ?= lib/provider/ebpf/bpf/headers
BPF_VMLINUX_HEADER ?= $(BPF_HEADERS_DIR)/vmlinux.h
BUILDVCS ?= false
BINDIR ?= .
DIST_DIR ?= dist
SIGMA_REPO_DIR ?=

LDFLAGS := -X main.version=$(VERSION)
AURORA_BIN := $(BINDIR)/aurora
AURORA_UTIL_BIN := $(BINDIR)/aurora-util

.PHONY: help build build-aurora build-aurora-util bpf-generate bpf-ensure test vet clean package

help:
	@echo "Targets:"
	@echo "  build              Build aurora and aurora-util in $(BINDIR)"
	@echo "  build-aurora       Build aurora binary"
	@echo "  build-aurora-util  Build aurora-util binary"
	@echo "  bpf-generate       Generate Linux eBPF bindings (bpftool + clang required)"
	@echo "  test               Run go test ./..."
	@echo "  vet                Run go vet ./..."
	@echo "  clean              Remove local build artifacts"
	@echo "  package            Build Linux package tarball (requires SIGMA_REPO_DIR)"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)"
	@echo "  GOOS=$(GOOS)"
	@echo "  GOARCH=$(GOARCH)"
	@echo "  BUILDVCS=$(BUILDVCS)"
	@echo "  BINDIR=$(BINDIR)"
	@echo "  DIST_DIR=$(DIST_DIR)"

build: build-aurora build-aurora-util

bpf-ensure:
	@if [[ "$(GOOS)" != "linux" ]]; then \
		exit 0; \
	fi
	@if ls lib/provider/ebpf/*_bpfel.go >/dev/null 2>&1; then \
		exit 0; \
	fi
	@if [[ "$(HOST_OS)" != "linux" ]]; then \
		echo "missing lib/provider/ebpf/*_bpfel.go for GOOS=linux and host is $(HOST_OS)." >&2; \
		echo "Generate files on a Linux host with: make bpf-generate" >&2; \
		exit 1; \
	fi
	@echo "generated eBPF bindings not found; running make bpf-generate"
	@$(MAKE) bpf-generate GOOS=$(GOOS) GOARCH=$(GOARCH) BUILDVCS=$(BUILDVCS)

bpf-generate:
	@if [[ "$(HOST_OS)" != "linux" ]]; then \
		echo "bpf-generate must run on Linux (host=$(HOST_OS))" >&2; \
		exit 1; \
	fi
	@command -v bpftool >/dev/null 2>&1 || { echo "bpftool not found in PATH"; exit 1; }
	@command -v clang >/dev/null 2>&1 || { echo "clang not found in PATH"; exit 1; }
	@[[ -f /sys/kernel/btf/vmlinux ]] || { echo "/sys/kernel/btf/vmlinux not found"; exit 1; }
	mkdir -p "$(BPF_HEADERS_DIR)"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$(BPF_VMLINUX_HEADER)"
	$(GO) generate ./lib/provider/ebpf/

build-aurora: bpf-ensure
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build -buildvcs=$(BUILDVCS) -ldflags "$(LDFLAGS)" -o "$(AURORA_BIN)" ./cmd/aurora

build-aurora-util:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build -buildvcs=$(BUILDVCS) -ldflags "$(LDFLAGS)" -o "$(AURORA_UTIL_BIN)" ./cmd/aurora-util

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -f "$(AURORA_BIN)" "$(AURORA_UTIL_BIN)"
	rm -f lib/provider/ebpf/*_bpfel.go lib/provider/ebpf/*_bpfel.o
	rm -rf "$(DIST_DIR)"

package:
	@if [[ -z "$(SIGMA_REPO_DIR)" ]]; then \
		echo "SIGMA_REPO_DIR is required (path to sigma repo root containing rules/linux)"; \
		exit 1; \
	fi
	mkdir -p "$(DIST_DIR)"
	@$(MAKE) bpf-ensure GOOS=linux GOARCH=$(GOARCH) BUILDVCS=$(BUILDVCS)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) \
		$(GO) build -buildvcs=$(BUILDVCS) -ldflags "$(LDFLAGS)" -o "$(DIST_DIR)/aurora-$(GOARCH)" ./cmd/aurora
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) \
		$(GO) build -buildvcs=$(BUILDVCS) -ldflags "$(LDFLAGS)" -o "$(DIST_DIR)/aurora-util-$(GOARCH)" ./cmd/aurora-util
	VERSION="$(VERSION)" \
	GOARCH="$(GOARCH)" \
	BINARY_PATH="$(DIST_DIR)/aurora-$(GOARCH)" \
	UTILITY_BINARY_PATH="$(DIST_DIR)/aurora-util-$(GOARCH)" \
	SIGMA_REPO_DIR="$(SIGMA_REPO_DIR)" \
	DIST_DIR="$(DIST_DIR)" \
	./scripts/build-package.sh
