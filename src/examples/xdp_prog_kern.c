#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define MAX_PACKET_SIZE 256

// Struct representing each invidiual packet event written to the pcap file
// NOTE: You may face verifier issues with pkt_data[] (the third field). If so,
// switch to a constant array size.
struct packet_event {
	__u64 timestamp_ns;
	__u32 pkt_len;
	__u8 pkt_data[MAX_PACKET_SIZE];
};

// Ring buffer storing packet events that will be written to a .pcap.gz file
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_events SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
	// Get pointers to packet memory
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	// Only process IPv4 and perform a bounds check
	struct ethhdr* eth = (struct ethhdr*)data;
	if ((void*)(eth + 1) > data_end) return XDP_PASS;
	if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

	// Only process TCP and UDP and perform a bounds check
	struct iphdr* ip = (struct iphdr*)(eth + 1);
	if ((void*)(ip + 1) > data_end) return XDP_PASS;
	__u8 ip_header_length = ip->ihl;
	if ((void*)ip + ip_header_length > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;

	__u32 pkt_len = data_end - data;
	if (pkt_len > MAX_PACKET_SIZE) pkt_len = MAX_PACKET_SIZE;

	// Reserve ring buffer memory for the packet entry
	struct packet_event* event = bpf_ringbuf_reserve(&packet_events, sizeof(struct packet_event), 0);
	if (!event) return XDP_PASS;

	// Fill in the packet entry instance
	event->timestamp_ns = bpf_ktime_get_ns();
	event->pkt_len = data_end - data;
	if (bpf_probe_read_kernel(event->pkt_data, pkt_len, data) < 0) {
		bpf_ringbuf_discard(event, 0);
		return XDP_PASS;
	}

	// Write the packet entry to the ring buffer
	bpf_ringbuf_submit(event, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

/*
	NOTE: Consider using the total length field from the IPv4 header instead
	of just doing __u32 pkt_len .

	bpf_ringbuf_reserve can't take variable length size parameters. IT REALLY DOESNT LIKE IT IF YOU TYPE
	IT IN DIRECTLY. MAYBE IT WILL WORK IF YOU JUST ENTER A SINGLE VARIABLE?

	bpf_probe_read_kernel is fine taking variable lengths as parameters
*/
