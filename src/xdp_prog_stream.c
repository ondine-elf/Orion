/*
    The following program is intended to stream packets to a ring buffer
    accessible in user space, then writing it to pcap.gz files. It currently
    does not work because of bpf verifier violations, and is still being worked on.
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PKT_LEN 256

struct packet_event_t {
    __u64 timestamp_ns;
    __u32 pkt_len;
    __u8 pkt_data[MAX_PKT_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __uint(key_size, 0);
    __uint(value_size, 0);
} packet_events SEC(".maps");


SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    if (pkt_len > MAX_PKT_LEN)
        pkt_len = MAX_PKT_LEN;

    __u32 total_size = sizeof(struct packet_event_t) + pkt_len;
    total_size = (total_size + 7) & ~7; // align to 8 bytes

    struct packet_event_t *evt = bpf_ringbuf_reserve(&packet_events, total_size, 0);
    if (!evt)
        return XDP_PASS;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pkt_len = pkt_len;

    if (bpf_probe_read_kernel(evt->pkt_data, pkt_len, data) < 0) {
        bpf_ringbuf_discard(evt, 0);
        return XDP_PASS;
    }

    bpf_ringbuf_submit(evt, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";