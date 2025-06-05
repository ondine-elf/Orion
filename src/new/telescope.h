#ifndef __TELESCOPE_H
#define __TELESCOPE_H

#include <linux/bpf.h>

#define MAX_PKT_LEN 256
struct packet_event_t {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 pkt_len;
    __u8 pkt_data[MAX_PKT_LEN];
};

#endif