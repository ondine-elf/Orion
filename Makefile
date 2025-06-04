# SRC := src/xdp_prog_stream.c
SRC := src/new_ring.c
IFACE=orion

run:
	# @xdp-loader unload -a $(IFACE)
	@clang \
		-O2 \
		-D __BPF_TRACING__ \
		-g \
		-Wall \
		-target bpf \
		-c $(SRC) \
		-o xdp_prog.o
	@xdp-loader load -v -m skb -s xdp -p /sys/fs/bpf $(IFACE) xdp_prog.o
	# @rm xdp_prog.o

clean:
	@xdp-loader unload -a $(IFACE)

status:
	@xdp-loader status $(IFACE)