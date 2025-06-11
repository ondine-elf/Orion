IFACE := wlo1
BUILD := build

PCAP_KERN := src/xdp_pcap_kern.c
PCAP_USER := src/xdp_pcap_user.c

FLOW_KERN := src/xdp_flow_kern.c
FLOW_USER := src/xdp_flow_user.c

.PHONY: pcap flow run-pcap run-flow stop clean

$(BUILD):
	mkdir -p $(BUILD)

pcap: $(BUILD)
	clang -O2 -g -Wall -target bpf -c $(PCAP_KERN) -o $(BUILD)/xdp_pcap_kern.o
	xdp-loader load -m skb -s xdp -p /sys/fs/bpf $(IFACE) $(BUILD)/xdp_pcap_kern.o

flow: $(BUILD)
	clang -O2 -g -Wall -target bpf -c $(FLOW_KERN) -o $(BUILD)/xdp_flow_kern.o
	xdp-loader load -m skb -s xdp -p /sys/fs/bpf $(IFACE) $(BUILD)/xdp_flow_kern.o

run-pcap: $(BUILD)
	gcc -O2 -Wall $(PCAP_USER) -o $(BUILD)/dump_pcap -lbpf -lz
	$(BUILD)/dump_pcap

run-flow: $(BUILD)
	gcc -O2 -Wall $(FLOW_USER) -o $(BUILD)/dump_flow -lbpf -lz
	$(BUILD)/dump_flow

stop:
	xdp-loader unload -a $(IFACE)

clean:
	rm -rf $(BUILD)

