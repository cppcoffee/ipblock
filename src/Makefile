CLANG := clang
LLVM_STRIP := llvm-strip
BPFTOOL := bpftool

CC := gcc
CFLAGS := -g -O2 -Wall -I/opt/libbpf/include/
LDFLAGS := -L/opt/libbpf/lib64
LIBS := -lbpf -lelf -lz
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

XDP_PROG := ipblock.bpf.o
APPS := ipblock-loader ipblock-rule

.PHONY: all
all: $(XDP_PROG) $(APPS)

.PHONY: clean
clean:
	rm -f $(XDP_PROG) $(APPS) ipblock.skel.h

ipblock.skel.h: ipblock.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

ipblock.bpf.o: ipblock.bpf.c
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@

ipblock-loader: ipblock.skel.h loader.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LIBS) -o $@

ipblock-rule: rule.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LIBS) -o $@
