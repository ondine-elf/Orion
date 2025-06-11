src = src/xdp_pcap_kern.c
dump_src = src/xdp_pcap_user.c
run:
	@clang -g -Wall -Wextra -O2 -target bpf -c $(src) -o build/xdp_prog_kern.o
	@xdp-loader load -m skb -s xdp -p /sys/fs/bpf wlo1 build/xdp_prog_kern.o

dump:
	@gcc -Wall -Wextra -O2 $(dump_src) -o build/dump -lbpf -lz
	@build/dump

stop:
	@xdp-loader unload -a wlo1
