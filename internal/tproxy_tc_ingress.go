package internal

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc "$CLANG" -strip "$STRIP" -makebase "$MAKEDIR" tproxy ../ebpf/tproxy/tproxy-tc-ingress2.c -- -mcpu=v2 -nostdinc -Wall -Werror -I../ebpf/include
