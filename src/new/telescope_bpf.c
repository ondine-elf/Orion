#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "telescope.h"

#define MAX_PKT_LEN 256

// Define a ring buffer map to hold packet events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} ringbuf_map SEC(".maps");


SEC("xdp")
int telescope_capture(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;
    struct ethhdr *eth = data;

    //// Bounds check: Packet length
    // Check if the packet length exceeds the maximum allowed length
    if (pkt_len > MAX_PKT_LEN) {
        // TODO: Log too large packet received
        return XDP_PASS; // Pass the packet without processing :(
    }
    
    //// Bounds check: Ethernet header
    // Check ethernet header isn't bigger than the packet! (Would mean invalid eth header)
    if ((void *)(eth + 1) > data_end) {
        // TODO: Log invalid ethernet header
        return XDP_PASS; // Pass the packet without processing :(
    }

    //// IPv4 Check
    // Check if the packet is an IPv4 packet
    // The Ethernet protocol type for IPv4 is ETH_P_IP (0x0800)
    // Note: __constant_htons is used to convert the protocol type to network byte order
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Extract IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    //// Bounds check: IP header
    // Check ip header isn't bigger than the packet! (Would mean invalid ip header)
    if ((void *)(ip + 1) > data_end) {
        // TODO: Log invalid ip header
        return XDP_PASS; // Pass the packet without processing :(
    }

    // Populate packet_event to send to userspace
    struct packet_event_t event;
    event.timestamp_ns = bpf_ktime_get_ns(); // or bpf_ktime_get_boot_ns();
    event.src_ip = bpf_ntohl(ip->saddr); // Convert to host byte order
    event.dst_ip = bpf_ntohl(ip->daddr); // Convert to host byte order
    event.protocol = ip->protocol;
    event.pkt_len = pkt_len;
    
    // Copy the packet data into the event structure
    if (pkt_len > sizeof(event.pkt_data)) {
        pkt_len = sizeof(event.pkt_data); // Limit to max size
    }
    if (bpf_probe_read_kernel(event.pkt_data, pkt_len, data) < 0) {
        // TODO: Log error reading packet data
        return XDP_PASS;
    }

    bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);
    
    bpf_printk("Submitted event to ringbuffer...");
    
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";