#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define MAX_MAP_ENTRIES 1024

/*
    Struct to which each packet is cast and then
    hashed, forming the keys in the flow map. This
    consists of the source and destination IPs, the
    source and destination ports, and the transport
    layer protocol (TCP / UDP).
*/
struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

/*
    Struct forming the value in each key-value pair
    in the flow map. This consists of a very basic
    packet-count for the duration of the connection,
    and a byte-count. Many additional fields could be added;
    This is just a proof of concept.
*/
struct flow_value_t {
    __u64 packets;
    __u64 bytes;
};

/*
    This is the actual struct in kernel memory where our flow map
    will be stored. In most cases, only the type, key / key_size,
    value / value_size and max_entries fields are required. For more
    details, see: https://docs.ebpf.io/linux/concepts/maps/

    LIBBPF_PIN_BY_NAME means that this program will pin the flow_map
    structure by its variable name (in this case, literally "flow_map")
    at /sys/fs/bpf/flow_map, thus making it accessible from user space.
    If you want to run a quick experiment, run the following commands:
    "sudo make run"
    "sudo watch -n1 cat /sys/fs/bpf/flow_map"
    Then, if you open a youtube video and slide the timer around a lot, you'll
    rightfully see that one of the entries will have its packet count and
    byte count jump up.

    IMPORTANT!!! Currently, for lookup efficiency, all entries are stored in
    network byte order so that no bit swapping needs to take place. Please
    take this into account when creating your userspace program.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __uint(key_size, sizeof(struct flow_key_t));
    __type(key, struct flow_key_t);
    __uint(value_size, sizeof(struct flow_value_t));
    __type(value, struct flow_value_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
    /*
        Get pointers to start and end of packet in memory. The "data"
        and "data_end" fields are originally 32-bit, so you first have to
        cast to 64 bits.
    */
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    
    /*
        Get Ethernet Header struct and pass the packet up to the kernel
        if it isn't an IPv4 packet. Also, perform a bounds check.
    */
    struct ethhdr* eth = (struct ethhdr*)data;
    if ((void*)eth + sizeof(struct ethhdr) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    /*
        Get IPv4 header and from it, fetch the source IP, destination IP,
        and protocol (TCP / UDP). For now, we will only work with TCP and UDP.
        Get the source and destination IPs and protocol field (TCP / UDP),
        and then get the source and destination ports from the TCP / UDP header.
        Finally, calculate the packet size as just the total number of bytes in
        the received Ethernet Frame (struct xdp_md* ctx).

        WARNING: The verifier for the eBPF programs is VERY strict. You need
        to perform a bounds check on all pointer accesses relating to the packet
        memory. In this case, if you fail to check if (void*)ip + ip_header_length
        is greater than data_end, uploading the program will fail and give you error -13.
    */
    struct iphdr* ip = (struct iphdr*)((void*)eth + sizeof(struct ethhdr));
    if ((void*)ip + sizeof(struct iphdr) > data_end) return XDP_PASS;
    __u8 ip_header_length = 4 * ip->ihl;
    if ((void*)ip + ip_header_length > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)((void*)ip + ip_header_length);
        if ((void*)tcp + sizeof(struct tcphdr) > data_end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)((void*)ip + ip_header_length);
        if ((void*)udp + sizeof(struct udphdr) > data_end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    }
    else return XDP_PASS;

    __u64 bytes = (__u64)(data_end - data);

    // Create new key for which we will either create or update the flow map entry
    struct flow_key_t key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol
    };

    /*
        If the key already exists in the flow map, update its value by
        1 packet (the current packet) and its byte count by said packet's
        byte count. Otherwise, create an entry for this key and assign
        it a single packet and said packet's byte count.
    */
    struct flow_value_t* value = bpf_map_lookup_elem(&flow_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, bytes);
    }
    else {
        struct flow_value_t new_value = {
            .packets = 1,
            .bytes = bytes
        };
        // Unsure of whether to use BPF_ANY or BPF_NOEXIST when taking into account failed lookups
        bpf_map_update_elem(&flow_map, &key, &new_value, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";