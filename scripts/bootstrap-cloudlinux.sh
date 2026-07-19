#!/usr/bin/env sh
set -eu

sudo -n dnf install -y \
    bpftool \
    clang \
    elfutils-libelf-devel \
    gcc \
    kernel-headers \
    libbpf-devel \
    llvm \
    make \
    pkgconf-pkg-config \
    zlib-devel
