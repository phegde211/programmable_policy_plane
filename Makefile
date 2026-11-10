CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

all: xdpctl

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

xdp_plane.bpf.o: xdp_plane.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

xdp_plane.skel.h: xdp_plane.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

xdpctl: xdpctl.c xdp_plane.skel.h
	$(CC) -O2 -g -o $@ $< -lbpf -lxdp -lelf -lz

clean:
	rm -f xdpctl xdp_plane.bpf.o xdp_plane.skel.h vmlinux.h

.PHONY: all clean
