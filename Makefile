.PHONY: build
build:
	clang -O2 -Wall -mcpu=v1 -g -target bpfel -c bpf.c -o bpf.o
	go build -o loader -gcflags="all=-N -l" ./

