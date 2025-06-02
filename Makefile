SRC := src/xdp_prog_stream.c

run:
	@clang -O2 -g -Wall -target bpf -c $(SRC) -o xdp_prog.o
	@xdp-loader load -m skb -s xdp -p /sys/fs/bpf wlo1 xdp_prog.o
	@rm xdp_prog.o

clean:
	@xdp-loader unload -a wlo1