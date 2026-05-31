# egresstop Makefile — compiles the BPF object to bin/egresstop.bpf.o.

BPF_CLANG ?= clang
BPFTOOL   ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

INCLUDE_DIR := include
BIN_DIR     := bin
VMLINUX     := $(INCLUDE_DIR)/vmlinux.h
BPF_SRC     := egresstop.bpf.c
BPF_OBJ     := $(BIN_DIR)/egresstop.bpf.o

.PHONY: all clean distclean
all: $(BPF_OBJ)

$(VMLINUX): | $(INCLUDE_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) | $(BIN_DIR)
	$(BPF_CLANG) -O2 -g -Wall -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I$(INCLUDE_DIR) -I/usr/include \
		-c $< -o $@

$(INCLUDE_DIR) $(BIN_DIR):
	@mkdir -p $@

clean:
	rm -rf $(BIN_DIR)

distclean: clean
	rm -rf $(INCLUDE_DIR)
