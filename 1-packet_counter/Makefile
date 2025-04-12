BPF_CLANG=clang
BPF_LLVM=llc
CFLAGS=-target bpf -Wall -O3 -g

all:
	$(BPF_CLANG) $(CFLAGS) -c counter.bpf.c -o counter.bpf.o