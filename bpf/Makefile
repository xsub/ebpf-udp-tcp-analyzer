BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Werror
BPF_CORE_CFLAGS ?= $(BPF_CFLAGS) -Wno-missing-declarations
CC ?= cc
HOST_CFLAGS ?= -O2 -g -Wall -Wextra -Werror
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_ARCH),x86_64)
BPF_ARCH := x86
else ifeq ($(UNAME_ARCH),aarch64)
BPF_ARCH := arm64
else ifeq ($(UNAME_ARCH),arm64)
BPF_ARCH := arm64
else ifeq ($(UNAME_ARCH),ppc64le)
BPF_ARCH := powerpc
else ifeq ($(UNAME_ARCH),s390x)
BPF_ARCH := s390
else ifeq ($(UNAME_ARCH),riscv64)
BPF_ARCH := riscv
else
BPF_ARCH := $(UNAME_ARCH)
endif

.PHONY: all full receive tcp-channel udp-channel clean

all: udp_ingress.bpf.o

full: all receive tcp-channel udp-channel

receive: udp_receive.bpf.o udp_receive_loader

tcp-channel: tcp_channel.bpf.o tcp_channel_loader

udp_ingress.bpf.o: udp_ingress.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

vmlinux.h:
	@test -r "$(VMLINUX_BTF)" || (echo "kernel BTF not found at $(VMLINUX_BTF)" >&2; exit 1)
	bpftool btf dump file "$(VMLINUX_BTF)" format c > $@.tmp
	mv $@.tmp $@

udp_receive.bpf.o: udp_receive.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CORE_CFLAGS) -D__TARGET_ARCH_$(BPF_ARCH) -I. -c $< -o $@

udp_receive_loader: udp_receive_loader.c
	$(CC) $(HOST_CFLAGS) $$(pkg-config --cflags libbpf) -o $@ $< $$(pkg-config --libs libbpf) -lelf -lz

tcp_channel.bpf.o: tcp_channel.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CORE_CFLAGS) -D__TARGET_ARCH_$(BPF_ARCH) -I. -c $< -o $@

tcp_channel_loader: tcp_channel_loader.c
	$(CC) $(HOST_CFLAGS) $$(pkg-config --cflags libbpf) -o $@ $< $$(pkg-config --libs libbpf) -lelf -lz

udp-channel: udp_channel.bpf.o udp_channel_loader

udp_channel.bpf.o: udp_channel.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CORE_CFLAGS) -D__TARGET_ARCH_$(BPF_ARCH) -I. -c $< -o $@

udp_channel_loader: udp_channel_loader.c
	$(CC) $(HOST_CFLAGS) $$(pkg-config --cflags libbpf) -o $@ $< $$(pkg-config --libs libbpf) -lelf -lz

clean:
	rm -f *.o udp_receive_loader tcp_channel_loader udp_channel_loader vmlinux.h vmlinux.h.tmp
