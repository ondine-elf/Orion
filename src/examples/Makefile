SRC_XDP := src/xdp_prog_kern.c
SRC_USER := src/xdp_prog_user.c
SRC_TEST := src/test.c

run:
	@clang -O2 -g -Wall -Wextra -target bpf -c $(SRC_XDP) -o build/xdp_prog_kern.o
	@gcc -O2 -Wall -Wextra $(SRC_USER) -o build/xdp_prog_user -lbpf
	@xdp-loader load -m skb -s xdp -p /sys/fs/bpf wlo1 build/xdp_prog_kern.o
	@sudo build/xdp_prog_user

stop:
	@xdp-loader unload -a wlo1
	@rm build/*
	@rm /sys/fs/bpf/packet_events

test:
	@gcc $(SRC_TEST) -o build/test -lz -lbpf
	@build/test
	
.PHONY: run stop test

#pkg-config --cflags --libs libbpf
